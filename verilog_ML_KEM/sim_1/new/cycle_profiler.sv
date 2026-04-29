// =============================================================================
// cycle_profiler.sv — Per-phase cycle counters for ML-KEM-768 thesis analysis.
//
// Bound to ml_kem_top via `bind` directive in tb_ml_kem_profile_wrapper.sv.
// Watches top-FSM state + selected engine activity signals (keccak din_valid,
// engine start/done windows). Per-op (KeyGen / Encaps / Decaps), accumulates
// cycle counts in logical buckets and dumps a CSV summary at $finish.
//
// Bucket definitions (per op):
//   total       : cycles from start_pulse to done (matches REG_CYCLES on-board)
//   axi_io      : cycles spent in S_MM_RD_* / S_MM_WR_* / S_ENCAPS_PRELOAD_* /
//                 S_DECAPS_PRELOAD_* (AXI-MM transfer phases)
//   compute     : cycles in S_KEYGEN_WAIT / S_ENCAPS_WAIT / S_DECAPS_WAIT
//                 (sub-modules running internally)
//   keccak      : cycles where shared u_keccak input is valid (top_k_din_valid)
//                 — proxy for "keccak is processing data this cycle"
//   non_keccak  : compute cycles that are not keccak active (NTT / CBD / Pointwise /
//                 Compress / Parse / Control)
//   control     : idle/transition cycles within the op (anything not in the above)
//
// Sum of (axi_io + compute + control) ≈ total. Sum of (keccak + non_keccak) ≈
// compute. Cross-validate per-op total against on-board REG_CYCLES (within ~0.1%).
// =============================================================================

module cycle_profiler (
    input wire        clk,
    input wire        rst_n,

    // Top FSM state observation
    input wire [7:0]  state,

    // Op start indicator (1-cycle pulse from AXI-Lite slave)
    input wire        start_pulse,
    input wire [1:0]  op_sel_latched,

    // Keccak activity proxy
    input wire        top_k_din_valid,
    input wire        top_k_dout_valid,

    // Lifted encrypt activity
    input wire        kpke_enc_busy
);

    // -------------------------------------------------------------------------
    // Top FSM state constants (mirror ml_kem_top.v)
    // -------------------------------------------------------------------------
    localparam [7:0] S_IDLE                    = 8'd0;
    localparam [7:0] S_KEYGEN_START            = 8'd1;
    localparam [7:0] S_KEYGEN_WAIT             = 8'd2;
    localparam [7:0] S_ENCAPS_READ_PK          = 8'd3;
    localparam [7:0] S_ENCAPS_READ_M           = 8'd4;
    localparam [7:0] S_ENCAPS_PRELOAD_EK_FETCH = 8'd5;
    localparam [7:0] S_ENCAPS_PRELOAD_M        = 8'd6;
    localparam [7:0] S_ENCAPS_START            = 8'd7;
    localparam [7:0] S_ENCAPS_WAIT             = 8'd8;
    localparam [7:0] S_DECAPS_READ_DK          = 8'd9;
    localparam [7:0] S_DECAPS_READ_CT          = 8'd10;
    localparam [7:0] S_DECAPS_PRELOAD_DK_FETCH = 8'd11;
    localparam [7:0] S_DECAPS_PRELOAD_CT_FETCH = 8'd12;
    localparam [7:0] S_DECAPS_START            = 8'd13;
    localparam [7:0] S_DECAPS_WAIT             = 8'd14;
    localparam [7:0] S_DONE                    = 8'd20;
    localparam [7:0] S_MM_RD_AR                = 8'd22;
    localparam [7:0] S_MM_RD_R                 = 8'd23;
    localparam [7:0] S_MM_WR_AW_W              = 8'd24;
    localparam [7:0] S_MM_WR_B                 = 8'd25;
    localparam [7:0] S_MM_WR_W                 = 8'd27;
    localparam [7:0] S_MM_WR_FETCH             = 8'd28;
    localparam [7:0] S_ENCAPS_PRELOAD_EK_SEND  = 8'd29;
    localparam [7:0] S_DECAPS_PRELOAD_DK_SEND  = 8'd30;
    localparam [7:0] S_DECAPS_PRELOAD_CT_SEND  = 8'd31;

    localparam [1:0] OP_KEYGEN = 2'd0;
    localparam [1:0] OP_ENCAPS = 2'd1;
    localparam [1:0] OP_DECAPS = 2'd2;

    // -------------------------------------------------------------------------
    // Per-op bucket counters
    // -------------------------------------------------------------------------
    integer cyc_total       [0:2];   // [op] : matches REG_CYCLES
    integer cyc_axi_io      [0:2];   // AXI-MM transfer phases
    integer cyc_compute     [0:2];   // S_*_WAIT (sub-module running)
    integer cyc_keccak      [0:2];   // keccak processing this cycle
    integer cyc_non_keccak  [0:2];   // compute cycles excluding keccak
    integer cyc_control     [0:2];   // idle/transition within op
    integer cyc_kpke_encrypt[0:2];   // lifted u_kpke_encrypt busy (encaps/decaps)

    integer i_init;

    initial begin
        for (i_init = 0; i_init < 3; i_init = i_init + 1) begin
            cyc_total[i_init]        = 0;
            cyc_axi_io[i_init]       = 0;
            cyc_compute[i_init]      = 0;
            cyc_keccak[i_init]       = 0;
            cyc_non_keccak[i_init]   = 0;
            cyc_control[i_init]      = 0;
            cyc_kpke_encrypt[i_init] = 0;
        end
    end

    // -------------------------------------------------------------------------
    // Op-active window detection (start_pulse → entry to S_DONE)
    // -------------------------------------------------------------------------
    reg [7:0] state_prev;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) state_prev <= S_IDLE;
        else        state_prev <= state;
    end

    wire op_done_event = (state == S_DONE) && (state_prev != S_DONE);

    reg op_active;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            op_active <= 1'b0;
        end else begin
            if (start_pulse)        op_active <= 1'b1;
            else if (op_done_event) op_active <= 1'b0;
        end
    end

    // -------------------------------------------------------------------------
    // Cycle classification
    // -------------------------------------------------------------------------
    wire is_axi_io =
        (state == S_MM_RD_AR)                 ||
        (state == S_MM_RD_R)                  ||
        (state == S_MM_WR_AW_W)               ||
        (state == S_MM_WR_W)                  ||
        (state == S_MM_WR_B)                  ||
        (state == S_MM_WR_FETCH)              ||
        (state == S_ENCAPS_READ_PK)           ||
        (state == S_ENCAPS_READ_M)            ||
        (state == S_ENCAPS_PRELOAD_EK_FETCH)  ||
        (state == S_ENCAPS_PRELOAD_EK_SEND)   ||
        (state == S_ENCAPS_PRELOAD_M)         ||
        (state == S_DECAPS_READ_DK)           ||
        (state == S_DECAPS_READ_CT)           ||
        (state == S_DECAPS_PRELOAD_DK_FETCH)  ||
        (state == S_DECAPS_PRELOAD_DK_SEND)   ||
        (state == S_DECAPS_PRELOAD_CT_FETCH)  ||
        (state == S_DECAPS_PRELOAD_CT_SEND);

    wire is_compute =
        (state == S_KEYGEN_WAIT) ||
        (state == S_ENCAPS_WAIT) ||
        (state == S_DECAPS_WAIT);

    wire keccak_active = top_k_din_valid || top_k_dout_valid;

    // -------------------------------------------------------------------------
    // Cycle accumulator (op-active gated)
    // -------------------------------------------------------------------------
    always @(posedge clk) begin
        if (rst_n && op_active) begin
            cyc_total[op_sel_latched] <= cyc_total[op_sel_latched] + 1;

            if (is_axi_io) begin
                cyc_axi_io[op_sel_latched] <= cyc_axi_io[op_sel_latched] + 1;
            end else if (is_compute) begin
                cyc_compute[op_sel_latched] <= cyc_compute[op_sel_latched] + 1;
                if (keccak_active) begin
                    cyc_keccak[op_sel_latched] <= cyc_keccak[op_sel_latched] + 1;
                end else begin
                    cyc_non_keccak[op_sel_latched] <= cyc_non_keccak[op_sel_latched] + 1;
                end
            end else begin
                cyc_control[op_sel_latched] <= cyc_control[op_sel_latched] + 1;
            end

            if (kpke_enc_busy) begin
                cyc_kpke_encrypt[op_sel_latched] <= cyc_kpke_encrypt[op_sel_latched] + 1;
            end
        end
    end

    // -------------------------------------------------------------------------
    // Per-op snapshot reset on start, dump on done
    // -------------------------------------------------------------------------
    always @(posedge clk) begin
        if (rst_n && start_pulse) begin
            cyc_total[op_sel_latched]        <= 0;
            cyc_axi_io[op_sel_latched]       <= 0;
            cyc_compute[op_sel_latched]      <= 0;
            cyc_keccak[op_sel_latched]       <= 0;
            cyc_non_keccak[op_sel_latched]   <= 0;
            cyc_control[op_sel_latched]      <= 0;
            cyc_kpke_encrypt[op_sel_latched] <= 0;
        end
    end

    // -------------------------------------------------------------------------
    // Per-op pretty print on done
    // -------------------------------------------------------------------------
    always @(posedge clk) begin
        if (rst_n && op_done_event) begin : print_dump
            integer op_idx;
            string  op_name;
            op_idx = op_sel_latched;
            case (op_idx)
                OP_KEYGEN: op_name = "KeyGen";
                OP_ENCAPS: op_name = "Encaps";
                OP_DECAPS: op_name = "Decaps";
                default:   op_name = "Unknown";
            endcase
            $display("");
            $display("=== CYCLE_PROFILE: %s ===", op_name);
            $display("  total        = %0d cyc  (matches REG_CYCLES on-board)", cyc_total[op_idx]);
            $display("  axi_io       = %0d cyc  (AXI-MM transfer phases)",      cyc_axi_io[op_idx]);
            $display("  compute      = %0d cyc  (sub-module running)",          cyc_compute[op_idx]);
            $display("    keccak     = %0d cyc  (din_valid|dout_valid)",        cyc_keccak[op_idx]);
            $display("    non_keccak = %0d cyc  (NTT/CBD/PW/Compress/etc.)",    cyc_non_keccak[op_idx]);
            $display("  control      = %0d cyc  (idle/transition within op)",   cyc_control[op_idx]);
            $display("  kpke_encrypt = %0d cyc  (lifted u_kpke_encrypt busy)",  cyc_kpke_encrypt[op_idx]);
            $display("  CSV: %s,%0d,%0d,%0d,%0d,%0d,%0d,%0d", op_name,
                     cyc_total[op_idx], cyc_axi_io[op_idx], cyc_compute[op_idx],
                     cyc_keccak[op_idx], cyc_non_keccak[op_idx],
                     cyc_control[op_idx], cyc_kpke_encrypt[op_idx]);
        end
    end

endmodule
