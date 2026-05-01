`timescale 1ns / 1ps

module ml_kem_encaps #(
    parameter HAS_INTERNAL_KECCAK  = 1,
    parameter HAS_INTERNAL_ENCRYPT = 1
) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    output reg          busy,
    output reg          done,

    // Input preload
    // in_sel = 0: ek (1184 bytes)
    // in_sel = 1: m  (32 bytes)
    input  wire         in_we,
    input  wire         in_sel,
    input  wire [10:0]  in_addr,
    input  wire [7:0]   in_wdata,

    // Output readback
    // out_sel = 0: ct, 1: ss
    input  wire         out_rd,
    input  wire         out_sel,
    input  wire [10:0]  out_addr,
    output reg  [7:0]   out_rdata,
    output reg          out_valid,

    // Streaming ciphertext output (from internal encrypt core)
    output wire         ct_we,
    output wire [10:0]  ct_addr,
    output wire [7:0]   ct_dout,

    // Packed shared secret output
    output reg  [255:0] ss_out,

    // External keccak interface, used only when HAS_INTERNAL_KECCAK == 0.
    output wire         ext_k_init,
    output wire [1:0]   ext_k_hash_type,
    output wire         ext_k_finalize,
    output wire [7:0]   ext_k_din,
    output wire         ext_k_din_valid,
    input  wire         ext_k_din_ready,
    input  wire [7:0]   ext_k_dout,
    input  wire         ext_k_dout_valid,
    output wire         ext_k_dout_ready,
    // R-new-A Phase E1: lane absorb path for H(ek) — exposes encaps's own
    // lane absorb signals to the shared sponge in ml_kem_top. Used only when
    // HAS_INTERNAL_KECCAK == 0.
    output wire         ext_k_absorb_lane_mode,
    output wire [63:0]  ext_k_lane_din,
    output wire         ext_k_lane_din_valid,
    input  wire         ext_k_lane_din_ready,

    // External kpke_encrypt interface (used only when HAS_INTERNAL_ENCRYPT == 0).
    // Forward signals: this module drives a shared kpke_encrypt instance hosted
    // at a parent module via these outputs.
    output wire         ext_enc_start,
    output wire         ext_enc_in_we,
    output wire [1:0]   ext_enc_in_sel,
    output wire [10:0]  ext_enc_in_addr,
    output wire [7:0]   ext_enc_in_wdata,
    // Backward signals: this module reads shared kpke_encrypt status via these
    // inputs.
    input  wire         ext_enc_busy,
    input  wire         ext_enc_done,
    input  wire         ext_enc_ct_we,
    input  wire [10:0]  ext_enc_ct_addr,
    input  wire [7:0]   ext_enc_ct_dout
);

    localparam [4:0] S_IDLE                 = 5'd0;
    localparam [4:0] S_HASH_H_INIT          = 5'd1;
    localparam [4:0] S_HASH_H_ABS           = 5'd2;  // send one byte to keccak
    localparam [4:0] S_HASH_H_FIN           = 5'd3;
    localparam [4:0] S_HASH_H_WAIT          = 5'd4;
    localparam [4:0] S_HASH_G_INIT          = 5'd5;
    localparam [4:0] S_HASH_G_ABS           = 5'd6;
    localparam [4:0] S_HASH_G_FIN           = 5'd7;
    localparam [4:0] S_HASH_G_WAIT          = 5'd8;
    localparam [4:0] S_ENC_PRELOAD          = 5'd9;
    localparam [4:0] S_ENC_START            = 5'd10;
    localparam [4:0] S_ENC_WAIT             = 5'd11;
    localparam [4:0] S_DONE                 = 5'd12;
    localparam [4:0] S_HASH_H_REQ           = 5'd13;
    localparam [4:0] S_ENC_PRELOAD_EK_REQ   = 5'd14;
    localparam [4:0] S_ENC_PRELOAD_EK_SEND  = 5'd15;
    localparam [4:0] S_HASH_H_RD_WAIT       = 5'd16;
    localparam [4:0] S_ENC_PRELOAD_EK_WAIT  = 5'd17;
    localparam [4:0] S_HASH_H_ADV           = 5'd18;

    reg [4:0] state;

    reg [7:0] m_buf  [0:31];
    reg         ek_rd_en;
    reg [10:0]  ek_rd_addr;
    wire [7:0]  ek_rd_data;
    reg         ct_rd_en;
    reg [10:0]  ct_rd_addr;
    wire [7:0]  ct_rd_data;
    reg         ct_rd_pending;
    reg         ct_rd_pending_d1;

    reg [7:0] h_buf  [0:31];
    reg [7:0] ss_buf [0:31];
    reg [7:0] r_buf  [0:31];

    reg         init_keccak;
    reg  [1:0]  hash_type;
    reg         finalize_keccak;
    reg  [7:0]  k_din;
    reg         k_din_valid;
    wire        k_din_ready;
    wire [7:0]  k_dout;
    wire        k_dout_valid;
    reg         fsm_k_dout_ready;
    // R-new-A Phase E1: lane absorb signals for encaps's own H absorb.
    // absorb_lane_mode_reg latched into the sponge at S_HASH_H_INIT (set 1
    // for SHA3-256 H); cleared at S_HASH_G_INIT (byte mode for SHA3-512 G).
    reg         absorb_lane_mode_reg;
    reg         lane_din_valid_reg;
    wire        lane_din_ready_w;

    reg         enc_start;
    reg         enc_in_we;
    reg  [1:0]  enc_in_sel;
    reg  [10:0] enc_in_addr;
    reg  [7:0]  enc_in_wdata;
    wire        enc_busy;
    wire        enc_done;
    wire        enc_ct_we;
    wire [10:0] enc_ct_addr;
    wire [7:0]  enc_ct_dout;
    wire        enc_k_init;
    wire [1:0]  enc_k_hash_type;
    wire        enc_k_finalize;
    wire [7:0]  enc_k_din;
    wire        enc_k_din_valid;
    wire        enc_k_din_ready;
    wire [7:0]  enc_k_dout;
    wire        enc_k_dout_valid;
    wire        enc_k_dout_ready;

    // When HAS_INTERNAL_ENCRYPT == 0, no local kpke_encrypt instance owns the
    // shared keccak — the lifted instance drives keccak directly via its own
    // ext_k_* path at the top level, so encaps's local MUX collapses to the
    // top-FSM (G/H hashing) source only.
    wire        enc_owns_keccak = (HAS_INTERNAL_ENCRYPT != 0) &&
                                  ((state == S_ENC_START) ||
                                   (state == S_ENC_WAIT));

    wire        shared_k_init       = enc_owns_keccak ? enc_k_init       : init_keccak;
    wire [1:0]  shared_k_hash_type  = enc_owns_keccak ? enc_k_hash_type  : hash_type;
    wire        shared_k_finalize   = enc_owns_keccak ? enc_k_finalize   : finalize_keccak;
    wire [7:0]  shared_k_din        = enc_owns_keccak ? enc_k_din        : k_din;
    wire        shared_k_din_valid  = enc_owns_keccak ? enc_k_din_valid  : k_din_valid;
    wire        shared_k_dout_ready = enc_owns_keccak ? enc_k_dout_ready : fsm_k_dout_ready;
    // R-new-A Phase E1: lane absorb only used by encaps's own H — kpke_encrypt
    // doesn't drive lane absorb (its PRF seed is 33B byte-aligned).
    wire        shared_k_absorb_lane_mode = enc_owns_keccak ? 1'b0 : absorb_lane_mode_reg;
    wire [63:0] shared_k_lane_din         = enc_owns_keccak ? 64'd0 : ek_rd_lane_data;
    wire        shared_k_lane_din_valid   = enc_owns_keccak ? 1'b0 : lane_din_valid_reg;
    wire        shared_k_din_ready;
    wire [7:0]  shared_k_dout;
    wire        shared_k_dout_valid;
    wire        shared_k_lane_din_ready;

    assign k_din_ready         = enc_owns_keccak ? 1'b0 : shared_k_din_ready;
    assign k_dout              = shared_k_dout;
    assign k_dout_valid        = enc_owns_keccak ? 1'b0 : shared_k_dout_valid;
    assign enc_k_din_ready     = enc_owns_keccak ? shared_k_din_ready : 1'b0;
    assign enc_k_dout          = enc_owns_keccak ? shared_k_dout : 8'd0;
    assign enc_k_dout_valid    = enc_owns_keccak ? shared_k_dout_valid : 1'b0;
    assign lane_din_ready_w    = enc_owns_keccak ? 1'b0 : shared_k_lane_din_ready;

    reg [11:0] var_k;
    integer i;

    assign ct_we   = enc_ct_we;
    assign ct_addr = enc_ct_addr;
    assign ct_dout = enc_ct_dout;

    // R-new-A Phase E1: ek_buf reorganized as 64-bit lane-wide BRAM with
    // byte-write enables (PS preload writes one byte at a time, crypto reads
    // one full lane at a time). 1184 bytes / 8 = 148 lanes (rounded up to
    // 256 lanes BRAM depth via BYTE_ADDR_WIDTH=11). Same BRAM18/36 count as
    // the prior byte-organized layout (Vivado packs 9472 bits identically).
    //
    // Byte-read API preserved: ek_rd_data is muxed out of ek_rd_lane_data
    // using ek_rd_addr[2:0] delayed 1 cycle to match the BRAM 1-cycle latency.
    wire [63:0] ek_rd_lane_data;
    reg  [2:0]  ek_rd_byte_pos_d1;

    xpm_ram_sdp_byte_write_lane_read #(
        .BYTE_ADDR_WIDTH(11),
        .DEPTH_BYTES(2048),
        .READ_LATENCY(1)
    ) u_ek_buf_ram (
        .clk          (clk),
        .wr_en        (in_we && !busy && !in_sel && (in_addr < 11'd1184)),
        .wr_addr      (in_addr),
        .wr_data      (in_wdata),
        .rd_en        (ek_rd_en),
        .rd_lane_addr (ek_rd_addr[10:3]),
        .rd_lane_data (ek_rd_lane_data)
    );

    // ek_rd_byte_pos_d1 latched in main FSM always block (see reset section).
    assign ek_rd_data = ek_rd_lane_data[ek_rd_byte_pos_d1*8 +: 8];

    xpm_ram_sdp_byte #(
        .ADDR_WIDTH(11),
        .DEPTH(2048),
        .READ_LATENCY(1)
    ) u_ct_buf_ram (
        .clk    (clk),
        .wr_en  (enc_ct_we && (enc_ct_addr < 11'd1088)),
        .wr_addr(enc_ct_addr),
        .wr_data(enc_ct_dout),
        .rd_en  (ct_rd_en),
        .rd_addr(ct_rd_addr),
        .rd_data(ct_rd_data)
    );

    generate
        if (HAS_INTERNAL_KECCAK) begin : gen_int_keccak
            keccak_sponge_top u_keccak (
                .clk(clk),
                .rst_n(rst_n),
                .init(shared_k_init),
                .hash_type(shared_k_hash_type),
                .finalize(shared_k_finalize),
                // R-new-A Phase E1: lane absorb driven by encaps's own H absorb
                .absorb_lane_mode(shared_k_absorb_lane_mode),
                .squeeze_lane_mode(1'b0),
                .din(shared_k_din),
                .din_valid(shared_k_din_valid),
                .din_ready(shared_k_din_ready),
                .lane_din(shared_k_lane_din),
                .lane_din_valid(shared_k_lane_din_valid),
                .lane_din_ready(shared_k_lane_din_ready),
                .dout(shared_k_dout),
                .dout_valid(shared_k_dout_valid),
                .dout_ready(shared_k_dout_ready),
                .lane_dout(),
                .lane_dout_valid(),
                .lane_dout_ready(1'b0)
            );

            assign ext_k_init             = 1'b0;
            assign ext_k_hash_type        = 2'b00;
            assign ext_k_finalize         = 1'b0;
            assign ext_k_din              = 8'd0;
            assign ext_k_din_valid        = 1'b0;
            assign ext_k_dout_ready       = 1'b0;
            // Phase E1: lane absorb ext outputs unused in internal-keccak mode
            assign ext_k_absorb_lane_mode = 1'b0;
            assign ext_k_lane_din         = 64'd0;
            assign ext_k_lane_din_valid   = 1'b0;
        end else begin : gen_ext_keccak
            assign ext_k_init         = shared_k_init;
            assign ext_k_hash_type    = shared_k_hash_type;
            assign ext_k_finalize     = shared_k_finalize;
            assign ext_k_din          = shared_k_din;
            assign ext_k_din_valid    = shared_k_din_valid;
            assign shared_k_din_ready = ext_k_din_ready;
            assign shared_k_dout      = ext_k_dout;
            assign shared_k_dout_valid = ext_k_dout_valid;
            assign ext_k_dout_ready   = shared_k_dout_ready;
            // R-new-A Phase E1: lane absorb flows out via ext_k_*lane*. Lane data
            // is the BRAM lane read directly (combinational). Lane mode goes high
            // during S_HASH_H_INIT (latched in sponge on init pulse).
            assign ext_k_absorb_lane_mode  = shared_k_absorb_lane_mode;
            assign ext_k_lane_din          = shared_k_lane_din;
            assign ext_k_lane_din_valid    = shared_k_lane_din_valid;
            assign shared_k_lane_din_ready = ext_k_lane_din_ready;
        end
    endgenerate

    generate
        if (HAS_INTERNAL_ENCRYPT) begin : gen_int_encrypt
            kpke_encrypt #(
                .HAS_INTERNAL_KECCAK(0)
            ) u_encrypt (
                .clk(clk),
                .rst_n(rst_n),
                .start(enc_start),
                .busy(enc_busy),
                .done(enc_done),
                .in_we(enc_in_we),
                .in_sel(enc_in_sel),
                .in_addr(enc_in_addr),
                .in_wdata(enc_in_wdata),
                .out_rd(1'b0),
                .out_addr(11'd0),
                .out_rdata(),
                .out_valid(),
                .ct_we(enc_ct_we),
                .ct_addr(enc_ct_addr),
                .ct_dout(enc_ct_dout),
                .ext_k_init(enc_k_init),
                .ext_k_hash_type(enc_k_hash_type),
                .ext_k_finalize(enc_k_finalize),
                .ext_k_din(enc_k_din),
                .ext_k_din_valid(enc_k_din_valid),
                .ext_k_din_ready(enc_k_din_ready),
                .ext_k_dout(enc_k_dout),
                .ext_k_dout_valid(enc_k_dout_valid),
                .ext_k_dout_ready(enc_k_dout_ready),
                // R-new-A Phase D2: lane PRF wired only in production (ml_kem_top).
                // ml_kem_encaps standalone TB falls back to byte path via tie-off.
                .ext_k_squeeze_lane_mode(),
                .ext_k_lane_dout(64'd0),
                .ext_k_lane_dout_valid(1'b0),
                .ext_k_lane_dout_ready()
            );

            // No external encrypt port driven in this branch.
            assign ext_enc_start    = 1'b0;
            assign ext_enc_in_we    = 1'b0;
            assign ext_enc_in_sel   = 2'b00;
            assign ext_enc_in_addr  = 11'd0;
            assign ext_enc_in_wdata = 8'd0;
        end else begin : gen_ext_encrypt
            // No local kpke_encrypt — drive the shared instance up at parent.
            assign ext_enc_start    = enc_start;
            assign ext_enc_in_we    = enc_in_we;
            assign ext_enc_in_sel   = enc_in_sel;
            assign ext_enc_in_addr  = enc_in_addr;
            assign ext_enc_in_wdata = enc_in_wdata;

            // Bring back encrypt status so the local FSM can sequence on it.
            assign enc_busy    = ext_enc_busy;
            assign enc_done    = ext_enc_done;
            assign enc_ct_we   = ext_enc_ct_we;
            assign enc_ct_addr = ext_enc_ct_addr;
            assign enc_ct_dout = ext_enc_ct_dout;

            // No local kpke_encrypt drives keccak; tie enc_k_* sources off so
            // the local keccak MUX (gated by enc_owns_keccak == 0) is clean.
            assign enc_k_init       = 1'b0;
            assign enc_k_hash_type  = 2'b00;
            assign enc_k_finalize   = 1'b0;
            assign enc_k_din        = 8'd0;
            assign enc_k_din_valid  = 1'b0;
            assign enc_k_dout_ready = 1'b0;
        end
    endgenerate

    always @(posedge clk) begin
        if (in_we && !busy) begin
            if (in_sel) begin
                if (in_addr < 11'd32) begin
                    m_buf[in_addr[4:0]] <= in_wdata;
                end
            end
        end
    end

    integer i_rst_buf;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state            <= S_IDLE;
            busy             <= 1'b0;
            done             <= 1'b0;
            out_rdata        <= 8'd0;
            out_valid        <= 1'b0;
            ek_rd_en         <= 1'b0;
            ek_rd_addr       <= 11'd0;
            ct_rd_en         <= 1'b0;
            ct_rd_addr       <= 11'd0;
            ct_rd_pending    <= 1'b0;
            ct_rd_pending_d1 <= 1'b0;
            ss_out           <= 256'd0;

            init_keccak           <= 1'b0;
            hash_type             <= 2'b00;
            finalize_keccak       <= 1'b0;
            k_din                 <= 8'd0;
            k_din_valid           <= 1'b0;
            fsm_k_dout_ready      <= 1'b0;
            // R-new-A Phase E1
            absorb_lane_mode_reg  <= 1'b0;
            lane_din_valid_reg    <= 1'b0;
            ek_rd_byte_pos_d1     <= 3'd0;

            enc_start             <= 1'b0;
            enc_in_we             <= 1'b0;
            enc_in_sel            <= 2'd0;
            enc_in_addr           <= 11'd0;
            enc_in_wdata          <= 8'd0;

            var_k                 <= 12'd0;

            // Explicit reset of buffer arrays. Without this, Vivado synth
            // emits [Synth 8-7137] "set and reset with same priority" and
            // warns of simulation mismatch — observed on KR260 as deterministic
            // encaps ct corruption (r polynomial degenerated to 0). Behavioral
            // sim doesn't see it because Verilog evaluates the conditional
            // assigns deterministically; on silicon, the synthesized flop
            // resolves the ambiguity differently.
            for (i_rst_buf = 0; i_rst_buf < 32; i_rst_buf = i_rst_buf + 1) begin
                h_buf[i_rst_buf]  <= 8'd0;
                ss_buf[i_rst_buf] <= 8'd0;
                r_buf[i_rst_buf]  <= 8'd0;
            end
        end else begin
            done                 <= 1'b0;
            out_valid            <= 1'b0;
            ek_rd_en             <= 1'b0;
            ct_rd_en             <= 1'b0;
            init_keccak          <= 1'b0;
            finalize_keccak      <= 1'b0;
            k_din_valid          <= 1'b0;
            // R-new-A Phase E1: lane_din_valid defaulted low; FSM holds high in ABS state.
            lane_din_valid_reg   <= 1'b0;
            enc_start            <= 1'b0;
            enc_in_we            <= 1'b0;

            // R-new-A Phase E1: latch ek_rd_addr[2:0] for byte mux 1 cycle later.
            if (ek_rd_en) ek_rd_byte_pos_d1 <= ek_rd_addr[2:0];

            // 2-stage pipe: stage1 (ct_rd_pending) issues BRAM read, stage2
            // (ct_rd_pending_d1) consumes ct_rd_data one cycle later when the
            // synchronous BRAM output has actually settled.
            ct_rd_pending_d1 <= ct_rd_pending;
            ct_rd_pending    <= 1'b0;

            if (ct_rd_pending_d1) begin
                out_valid <= 1'b1;
                out_rdata <= ct_rd_data;
            end

            if (out_rd) begin
                out_valid <= 1'b1;
                if (!out_sel) begin
                    if (out_addr < 11'd1088) begin
                        out_valid <= 1'b0;
                        ct_rd_en <= 1'b1;
                        ct_rd_addr <= out_addr;
                        ct_rd_pending <= 1'b1;
                    end else begin
                        out_rdata        <= 8'd0;
                        ct_rd_pending    <= 1'b0;
                        ct_rd_pending_d1 <= 1'b0;
                    end
                end else begin
                    if (out_addr < 11'd32) out_rdata <= ss_buf[out_addr[4:0]];
                    else                   out_rdata <= 8'd0;
                end
            end

            case (state)
                S_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        busy  <= 1'b1;
                        var_k <= 12'd0;
                        ct_rd_pending    <= 1'b0;
                        ct_rd_pending_d1 <= 1'b0;
                        // Soft-clear buffer arrays on every start. Without this,
                        // residual data persists between operations and causes
                        // subsequent calls to misbehave (verified on KR260).
                        for (i_rst_buf = 0; i_rst_buf < 32; i_rst_buf = i_rst_buf + 1) begin
                            h_buf[i_rst_buf]  <= 8'd0;
                            ss_buf[i_rst_buf] <= 8'd0;
                            r_buf[i_rst_buf]  <= 8'd0;
                        end
                        state <= S_HASH_H_INIT;
                    end
                end

                // h = SHA3-256(ek) — R-new-A Phase E1: lane absorb path.
                // 1184 bytes = 148 lanes (multiple of 8). 3 cyc/lane (REQ→ABS
                // wait-for-BRAM→ABS handshake) gives ~445 absorb cycles + ~9
                // perm × 24 = ~660 cyc total vs the prior ~4736 cyc byte-mode
                // path — saves ~4000 cyc per Encaps.
                S_HASH_H_INIT: begin
                    init_keccak          <= 1'b1;
                    hash_type            <= 2'b10; // SHA3-256
                    absorb_lane_mode_reg <= 1'b1;  // Phase E1: lane absorb
                    var_k                <= 12'd0; // doubles as lane_idx in lane mode
                    state                <= S_HASH_H_REQ;
                end

                // Lane request: var_k[7:0] is the lane index (0..147).
                S_HASH_H_REQ: begin
                    ek_rd_en   <= 1'b1;
                    ek_rd_addr <= {var_k[7:0], 3'd0}; // lane_idx*8 byte addr
                    state      <= S_HASH_H_ABS;
                end

                // Lane absorb. lane_din_valid_reg is registered (1-cycle lag
                // from being asserted), so the handshake check requires both
                // valid AND ready — otherwise the FIRST cycle of ABS would
                // see valid_reg=0 (still propagating) but ready=1 (sponge
                // already in ABSORB_LANE), and the FSM would falsely advance
                // without an actual sponge XOR.
                S_HASH_H_ABS: begin
                    lane_din_valid_reg <= 1'b1;
                    if (lane_din_valid_reg && lane_din_ready_w) begin
                        lane_din_valid_reg <= 1'b0;
                        if (var_k == 12'd147) begin
                            state <= S_HASH_H_FIN;
                        end else begin
                            var_k <= var_k + 12'd1;
                            state <= S_HASH_H_REQ;
                        end
                    end
                end

                // Legacy byte states retained as no-ops (lane FSM only uses
                // REQ + ABS but legacy state localparams kept for compat).
                S_HASH_H_RD_WAIT: state <= S_HASH_H_ABS;
                S_HASH_H_ADV:     state <= S_HASH_H_ABS;

                S_HASH_H_FIN: begin
                    finalize_keccak <= 1'b1;
                    fsm_k_dout_ready <= 1'b1;
                    var_k <= 12'd0;
                    state <= S_HASH_H_WAIT;
                end

                S_HASH_H_WAIT: begin
                    if (k_dout_valid && fsm_k_dout_ready) begin
                        h_buf[var_k[4:0]] <= k_dout;
                        var_k <= var_k + 12'd1;
                        if (var_k == 12'd31) begin
                            fsm_k_dout_ready <= 1'b0;
                            var_k <= 12'd0;
                            state <= S_HASH_G_INIT;
                        end
                    end
                end

                // (K, r) = SHA3-512(m || h)
                S_HASH_G_INIT: begin
                    init_keccak          <= 1'b1;
                    hash_type            <= 2'b11; // SHA3-512
                    absorb_lane_mode_reg <= 1'b0;  // Phase E1: byte absorb for G
                    var_k                <= 12'd0;
                    k_din                <= m_buf[5'd0];
                    k_din_valid          <= 1'b1;
                    state                <= S_HASH_G_ABS;
                end

                S_HASH_G_ABS: begin
                    k_din_valid <= 1'b1;
                    if (k_din_ready) begin
                        if (var_k == 12'd63) begin
                            k_din_valid <= 1'b0;
                            state <= S_HASH_G_FIN;
                        end else begin
                            var_k       <= var_k + 12'd1;
                            if (var_k < 12'd31) begin
                                k_din <= m_buf[var_k[4:0] + 5'd1];
                            end else begin
                                k_din <= h_buf[var_k - 12'd31];
                            end
                        end
                    end
                end
                S_HASH_G_FIN: begin
                    finalize_keccak <= 1'b1;
                    fsm_k_dout_ready <= 1'b1;
                    var_k <= 12'd0;
                    state <= S_HASH_G_WAIT;
                end

                S_HASH_G_WAIT: begin
                    if (k_dout_valid && fsm_k_dout_ready) begin
                        if (var_k < 12'd32) begin
                            ss_buf[var_k[4:0]] <= k_dout;
                            ss_out[var_k[4:0]*8 +: 8] <= k_dout;
                        end else begin
                            r_buf[var_k - 12'd32] <= k_dout;
                        end
                        var_k <= var_k + 12'd1;
                        if (var_k == 12'd63) begin
                            fsm_k_dout_ready <= 1'b0;
                            var_k <= 12'd0;
                            state <= S_ENC_PRELOAD;
                        end
                    end
                end

                // Preload encrypt core with ek/m/r
                S_ENC_PRELOAD: begin
                    if (var_k < 12'd1184) begin
                        state <= S_ENC_PRELOAD_EK_REQ;
                    end else if (var_k < 12'd1216) begin
                        enc_in_we    <= 1'b1;
                        enc_in_sel   <= 2'd1;
                        enc_in_addr  <= var_k[10:0] - 11'd1184;
                        enc_in_wdata <= m_buf[var_k - 12'd1184];
                        var_k        <= var_k + 12'd1;
                    end else if (var_k < 12'd1248) begin
                        enc_in_we    <= 1'b1;
                        enc_in_sel   <= 2'd2;
                        enc_in_addr  <= var_k[10:0] - 11'd1216;
                        enc_in_wdata <= r_buf[var_k - 12'd1216];
                        if (var_k == 12'd1247) begin
                            var_k <= 12'd0;
                            state <= S_ENC_START;
                        end else begin
                            var_k <= var_k + 12'd1;
                        end
                    end else begin
                        var_k <= 12'd0;
                        state <= S_ENC_START;
                    end
                end

                S_ENC_PRELOAD_EK_REQ: begin
                    ek_rd_en   <= 1'b1;
                    ek_rd_addr <= var_k[10:0];
                    state      <= S_ENC_PRELOAD_EK_WAIT;
                end

                // Align EK preload with synchronous BRAM read latency.
                S_ENC_PRELOAD_EK_WAIT: begin
                    state <= S_ENC_PRELOAD_EK_SEND;
                end

                S_ENC_PRELOAD_EK_SEND: begin
                    enc_in_we    <= 1'b1;
                    enc_in_sel   <= 2'd0;
                    enc_in_addr  <= var_k[10:0];
                    enc_in_wdata <= ek_rd_data;
                    var_k        <= var_k + 12'd1;
                    state        <= S_ENC_PRELOAD;
                end

                S_ENC_START: begin
                    enc_start <= 1'b1;
                    state <= S_ENC_WAIT;
                end

                S_ENC_WAIT: begin
                    if (enc_done) begin
                        state <= S_DONE;
                    end
                end

                S_DONE: begin
                    busy <= 1'b0;
                    done <= 1'b1;
                    state <= S_IDLE;
                end

                default: begin
                    state <= S_IDLE;
                end
            endcase
        end
    end

endmodule
