`timescale 1ns / 1ps

module ml_kem_keygen #(
    parameter HAS_INTERNAL_KECCAK = 1,
    parameter HAS_INTERNAL_POLY   = 1
) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    output reg          done,

    // Random seeds input (32 bytes each)
    input  wire [255:0] seed_d_in,
    input  wire [255:0] seed_z_in,

    // Output Memory Ports
    // pk is 1184 bytes
    output wire         pk_we,
    output wire [10:0]  pk_addr,  // 0 to 1183
    output wire [7:0]   pk_dout,

    // sk is 2400 bytes
    output wire         sk_we,
    output wire [11:0]  sk_addr,  // 0 to 2399
    output wire [7:0]   sk_dout,

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
    // R-new-A Phase E2: lane absorb path for H(ek) — exposes keygen's own
    // lane absorb signals to the shared sponge in ml_kem_top. Used only when
    // HAS_INTERNAL_KECCAK == 0.
    output wire         ext_k_absorb_lane_mode,
    output wire [63:0]  ext_k_lane_din,
    output wire         ext_k_lane_din_valid,
    input  wire         ext_k_lane_din_ready,

    // Step R3: external shared poly-engine interface, used only when
    // HAS_INTERNAL_POLY == 0. Mirrors the kpke_encrypt/kpke_decrypt patterns
    // added in Step 3.1, so the top-level can route keygen's NTT/PW/add
    // requests to the same u_shared_* instances.
    output wire         ext_ntt_start,
    input  wire         ext_ntt_done,
    output wire         ext_ntt_host_we,
    output wire [7:0]   ext_ntt_host_addr,
    output wire [15:0]  ext_ntt_host_din,
    input  wire [15:0]  ext_ntt_host_dout,

    output wire         ext_pw_start,
    input  wire         ext_pw_done,
    output wire         ext_pw_host_sel,
    output wire         ext_pw_host_we,
    output wire [7:0]   ext_pw_host_addr,
    output wire [15:0]  ext_pw_host_din,
    input  wire [15:0]  ext_pw_host_dout,

    output wire         ext_add_start,
    output wire         ext_add_is_sub,
    input  wire         ext_add_done,
    output wire         ext_add_host_sel,
    output wire         ext_add_host_we,
    output wire [7:0]   ext_add_host_addr,
    output wire [15:0]  ext_add_host_din,
    input  wire [15:0]  ext_add_host_dout
);

    // =================================================================
    // FSM States
    // =================================================================
    localparam S_IDLE              = 6'd0;
    localparam S_HASH_G            = 6'd1;
    localparam S_HASH_G_WAIT       = 6'd2;
    localparam S_HASH_G_FINAL      = 6'd35;

    localparam S_GEN_NOISE_INIT    = 6'd3;
    localparam S_PRF_SHAKE256      = 6'd4;
    localparam S_PRF_WAIT          = 6'd5;
    localparam S_PRF_FINAL         = 6'd36;

    localparam S_CBD               = 6'd6;
    localparam S_CBD_WAIT          = 6'd7;
    localparam S_PUMP_S_TO_NTT     = 6'd8;
    localparam S_RUN_NTT           = 6'd9;
    localparam S_PUMP_NTT_TO_S     = 6'd10;

    localparam S_MAT_MUL_INIT      = 6'd11;
    localparam S_PUMP_E_TO_ADD     = 6'd12;
    localparam S_MAT_MUL_J_INIT    = 6'd13;
    localparam S_XOF_A             = 6'd14;
    localparam S_XOF_WAIT          = 6'd15;
    localparam S_XOF_FINAL         = 6'd37;
    localparam S_XOF_PARSE_START   = 6'd38;

    localparam S_PUMP_S_TO_PW      = 6'd17;
    localparam S_RUN_PW            = 6'd18;
    localparam S_PUMP_PW_TO_ADD    = 6'd19;
    localparam S_RUN_ADD           = 6'd20;
    localparam S_RUN_ADD_WAIT      = 6'd34;

    localparam S_PUMP_ADD_TO_PKBUF = 6'd21;
    localparam S_DUMP_PK           = 6'd22;
    localparam S_DUMP_PK_WAIT      = 6'd23;

    localparam S_PACK_PK           = 6'd24;
    localparam S_HASH_H_PK         = 6'd25; // request read from pk_buf
    localparam S_HASH_H_WAIT       = 6'd26;

    localparam S_PACK_SK_SHAT      = 6'd27;
    localparam S_PACK_SK_SHAT_WAIT = 6'd28;
    localparam S_PACK_SK_PK        = 6'd29; // request read from pk_buf
    localparam S_PACK_SK_HPK       = 6'd30;
    localparam S_PACK_SK_Z         = 6'd31;
    localparam S_DONE              = 6'd32;

    localparam S_PUMP              = 6'd33;
    localparam S_HASH_H_PK_SEND    = 6'd41;
    localparam S_PACK_SK_PK_WRITE  = 6'd42;
    localparam S_PACK_SK_PK_WAIT   = 6'd43;
    localparam S_HASH_H_PK_WAIT    = 6'd44;

    reg [5:0] state;

    // =================================================================
    // Internal Registers
    // =================================================================
    // Step R5: LUTRAM hints. Each is 32 bytes filled sequentially by SHAKE
    // output (var_k 0..31 for rho/sigma; separate path for h_pk). All entries
    // are written before any read, so the soft-clear-on-start that the
    // previous design used (silicon "first pk replay" workaround) is no
    // longer needed once Vivado treats them as deterministic LUTRAM cells
    // rather than FF arrays. The for-loop reset below has been removed
    // accordingly — same fix pattern as Step 1 prf_buf.
    (* ram_style = "distributed" *) reg [7:0] rho_reg [0:31];
    (* ram_style = "distributed" *) reg [7:0] sigma_reg [0:31];
    (* ram_style = "distributed" *) reg [7:0] h_pk_reg [0:31];
    
    // Keccak Buffers
    // BRAM-friendly canonical pattern: no async/sync reset, single-port write
    // in dedicated always block. PRF_WAIT writes all 16 words before CBD reads,
    // so stale-on-reset is harmless (verified by S_PRF_WAIT -> S_CBD_WAIT flow).
    (* ram_style = "block" *) reg [63:0] prf_buf [0:15];
    reg [63:0] prf_buf_rdata;
    reg [3:0]  prf_word_idx;
    reg [2:0]  prf_byte_idx;
    reg [63:0] prf_shift;
    
    // Loop counters
    reg [2:0] i_idx;
    reg [2:0] j_idx;
    reg [11:0] var_k;

    // Pump controller
    reg [5:0] pump_ret_state;
    reg [8:0] pump_cnt;
    reg [3:0] pump_src_sel;
    reg [3:0] pump_dst_sel;
    reg       pump_we;
    reg [7:0] pump_rd_addr;
    reg [7:0] pump_wr_addr;
    reg [7:0] pump_len;
    reg       pump_op_kick_ntt;

    localparam SRC_S0 = 4'd0, SRC_S1 = 4'd1, SRC_S2 = 4'd2;
    localparam SRC_E0 = 4'd3, SRC_E1 = 4'd4, SRC_E2 = 4'd5;
    localparam SRC_AHAT = 4'd6, SRC_NTT = 4'd7, SRC_PW = 4'd8, SRC_ADD = 4'd9;

    localparam DST_S0 = 4'd0, DST_S1 = 4'd1, DST_S2 = 4'd2;
    localparam DST_E0 = 4'd3, DST_E1 = 4'd4, DST_E2 = 4'd5;
    localparam DST_AHAT = 4'd6, DST_NTT = 4'd7;
    localparam DST_PW_A = 4'd8, DST_PW_B = 4'd9, DST_ADD_A = 4'd10, DST_ADD_B = 4'd11;

    // Data Extraction Helpers
    wire [7:0] seed_d_byte;
    assign seed_d_byte = seed_d_in[var_k[4:0] * 8 +: 8];

    wire [7:0] seed_z_byte;
    assign seed_z_byte = seed_z_in[var_k[4:0] * 8 +: 8];

    // R-new-A Phase E2: pk_buf reorganized as 64-bit lane-wide BRAM with
    // byte-write enables. PS-side AXI / internal pk pack writes 1 byte per
    // cycle (pk_we + pk_addr + pk_dout); H absorb reads 1 lane per cycle;
    // legacy byte-read paths (S_PACK_SK_PK) reuse a 1-cycle delayed byte
    // mux on the lane data. Same BRAM18/36 count as the prior byte-organized
    // layout (2048 bytes × 8 = 256 lanes × 64 = 16384 bits).
    reg  [10:0] pk_buf_rd_addr;
    reg         pk_buf_rd_en;
    wire [7:0]  pk_buf_rd_data;
    wire [63:0] pk_buf_rd_lane_data;
    reg  [2:0]  pk_buf_rd_byte_pos_d1;

    xpm_ram_sdp_byte_write_lane_read #(
        .BYTE_ADDR_WIDTH(11),
        .DEPTH_BYTES(2048),
        .READ_LATENCY(1)
    ) u_pk_buf (
        .clk          (clk),
        .wr_en        (pk_we),
        .wr_addr      (pk_addr),
        .wr_data      (pk_dout),
        .rd_en        (pk_buf_rd_en),
        .rd_lane_addr (pk_buf_rd_addr[10:3]),
        .rd_lane_data (pk_buf_rd_lane_data)
    );

    // Byte-mux the lane data for legacy byte-read paths. Byte position is
    // captured 1 cycle after rd_en to align with BRAM 1-cycle latency.
    assign pk_buf_rd_data = pk_buf_rd_lane_data[pk_buf_rd_byte_pos_d1*8 +: 8];

    // =================================================================
    // BRAM Array (7 x True Dual Port 256x16)
    // =================================================================
    reg  [7:0]  ram_addr_a [0:6];
    reg  [7:0]  ram_addr_b [0:6];
    reg  [15:0] ram_din_a [0:6];
    reg  [15:0] ram_din_b [0:6];
    reg         ram_we_a [0:6];
    reg         ram_we_b [0:6];
    wire [15:0] ram_dout_a [0:6];
    wire [15:0] ram_dout_b [0:6];

    genvar g;
    generate
        for (g = 0; g < 7; g = g + 1) begin : gen_bram
            // True Dual Port Ram (BRAM18K)
            (* ram_style = "block" *) reg [15:0] mem [0:255];
            reg [15:0] out_a, out_b;
`ifndef SYNTHESIS
            // Initialize in simulation to reduce X-propagation during bring-up.
            integer i;
            initial begin
                for (i = 0; i < 256; i = i + 1) mem[i] = 16'd0;
            end
`endif
            always @(posedge clk) begin
                if (ram_we_a[g]) mem[ram_addr_a[g]] <= ram_din_a[g];
                out_a <= mem[ram_addr_a[g]];
            end
            always @(posedge clk) begin
                if (ram_we_b[g]) mem[ram_addr_b[g]] <= ram_din_b[g];
                out_b <= mem[ram_addr_b[g]];
            end
            assign ram_dout_a[g] = out_a;
            assign ram_dout_b[g] = out_b;
        end
    endgenerate

    // =================================================================
    // Instantiate IP Cores
    // =================================================================

    // 1. Keccak Sponge
    reg         init_keccak;
    reg  [1:0]  hash_type;
    reg         finalize_keccak;
    reg  [7:0]  k_din;
    reg         k_din_valid;
    wire        k_din_ready;
    wire [7:0]  k_dout;
    wire        k_dout_valid;
    reg         fsm_k_dout_ready;
    wire        parse_k_dout_ready;
    // R-new-A Phase E2: lane absorb signals for keygen's H(ek). Latched at
    // S_HASH_H_PK init (set 1 for SHA3-256), cleared on next sponge init
    // (G/PRF/XOF use byte mode). Phase E1 used the same pattern in encaps.
    reg         absorb_lane_mode_reg;
    reg         lane_din_valid_reg;
    wire        lane_din_ready_w;

    wire k_dout_ready = (state == S_XOF_WAIT) ? parse_k_dout_ready : fsm_k_dout_ready;

    generate
        if (HAS_INTERNAL_KECCAK) begin : gen_int_keccak
            keccak_sponge_top u_keccak (
                .clk(clk), .rst_n(rst_n),
                .init(init_keccak), .hash_type(hash_type), .finalize(finalize_keccak),
                .absorb_lane_mode(absorb_lane_mode_reg), .squeeze_lane_mode(1'b0),
                .din(k_din), .din_valid(k_din_valid), .din_ready(k_din_ready),
                .lane_din(pk_buf_rd_lane_data), .lane_din_valid(lane_din_valid_reg), .lane_din_ready(lane_din_ready_w),
                .dout(k_dout), .dout_valid(k_dout_valid), .dout_ready(k_dout_ready),
                .lane_dout(), .lane_dout_valid(), .lane_dout_ready(1'b0)
            );

            assign ext_k_init             = 1'b0;
            assign ext_k_hash_type        = 2'b00;
            assign ext_k_finalize         = 1'b0;
            assign ext_k_din              = 8'd0;
            assign ext_k_din_valid        = 1'b0;
            assign ext_k_dout_ready       = 1'b0;
            // Phase E2: lane absorb ext outputs unused in internal-keccak mode
            assign ext_k_absorb_lane_mode = 1'b0;
            assign ext_k_lane_din         = 64'd0;
            assign ext_k_lane_din_valid   = 1'b0;
        end else begin : gen_ext_keccak
            assign ext_k_init       = init_keccak;
            assign ext_k_hash_type  = hash_type;
            assign ext_k_finalize   = finalize_keccak;
            assign ext_k_din        = k_din;
            assign ext_k_din_valid  = k_din_valid;
            assign k_din_ready      = ext_k_din_ready;
            assign k_dout           = ext_k_dout;
            assign k_dout_valid     = ext_k_dout_valid;
            assign ext_k_dout_ready = k_dout_ready;
            // R-new-A Phase E2: lane absorb path — flows out via ext_k_*lane*.
            assign ext_k_absorb_lane_mode = absorb_lane_mode_reg;
            assign ext_k_lane_din         = pk_buf_rd_lane_data;
            assign ext_k_lane_din_valid   = lane_din_valid_reg;
            assign lane_din_ready_w       = ext_k_lane_din_ready;
        end
    endgenerate

    // For HAS_INTERNAL_KECCAK=1 path, lane_din_ready_w is driven directly by
    // the local sponge instantiation (declared as a wire). When
    // HAS_INTERNAL_KECCAK=0, lane_din_ready_w is assigned in gen_ext_keccak.
    // No extra wiring needed here.

    // 2. Poly CBD Eta2
    reg         cbd_start;
    wire        cbd_done;
    wire [3:0]  cbd_buf_addr;
    // 1-cycle sync read for BRAM inference (CBD module's READ_WORD->PROCESS
    // FSM is designed for this latency — see comment in poly_cbd_eta2_top).
    wire [63:0] cbd_buf_dout = prf_buf_rdata;
    always @(posedge clk) begin
        prf_buf_rdata <= prf_buf[cbd_buf_addr];
    end

    // Dedicated single-port BRAM write block (no reset, single write port).
    wire        prf_buf_we_w    = (state == S_PRF_WAIT) && k_dout_valid && (prf_byte_idx == 3'd7);
    wire [3:0]  prf_buf_waddr_w = prf_word_idx;
    wire [63:0] prf_buf_wdata_w = {k_dout, prf_shift[63:8]};
    always @(posedge clk) begin
        if (prf_buf_we_w) begin
            prf_buf[prf_buf_waddr_w] <= prf_buf_wdata_w;
        end
    end
    wire        cbd_ram_we;
    wire [6:0]  cbd_ram_addr;
    wire [15:0] cbd_ram_a0_din;
    wire [15:0] cbd_ram_a1_din;

    poly_cbd_eta2_top u_cbd (
        .clk(clk), .rst_n(rst_n), .start(cbd_start), .done(cbd_done),
        .buf_addr(cbd_buf_addr), .buf_dout(cbd_buf_dout),
        .ram_we(cbd_ram_we), .ram_addr(cbd_ram_addr), 
        .ram_a0_din(cbd_ram_a0_din), .ram_a1_din(cbd_ram_a1_din)
    );

    // 3. NTT Top
    reg         ntt_start;
    wire        ntt_done;
    wire        ntt_host_we;
    wire [7:0]  ntt_host_addr;
    wire [15:0] ntt_host_din;
    wire [15:0] ntt_host_dout;

    generate
        if (HAS_INTERNAL_POLY) begin : gen_int_ntt
            ntt_top u_ntt (
                .clk(clk), .rst_n(rst_n), .start(ntt_start), .done(ntt_done),
                .host_we(ntt_host_we), .host_addr(ntt_host_addr),
                .host_din(ntt_host_din), .host_dout(ntt_host_dout)
            );
            assign ext_ntt_start     = 1'b0;
            assign ext_ntt_host_we   = 1'b0;
            assign ext_ntt_host_addr = 8'd0;
            assign ext_ntt_host_din  = 16'd0;
        end else begin : gen_ext_ntt
            assign ext_ntt_start     = ntt_start;
            assign ext_ntt_host_we   = ntt_host_we;
            assign ext_ntt_host_addr = ntt_host_addr;
            assign ext_ntt_host_din  = ntt_host_din;
            assign ntt_done      = ext_ntt_done;
            assign ntt_host_dout = ext_ntt_host_dout;
        end
    endgenerate

    // 4. Poly Parse Inline Top
    reg         parse_start;
    wire        parse_done;
    wire        parse_ram_we_a0;
    wire        parse_ram_we_a1;
    wire [6:0]  parse_ram_addr;
    wire [15:0] parse_ram_a0_din;
    wire [15:0] parse_ram_a1_din;

//    wire        parse_k_dout_ready;

    poly_parse_inline_top u_parse (
        .clk(clk), .rst_n(rst_n), .start(parse_start), .done(parse_done),
        .shake_dout(k_dout), .shake_dout_valid(k_dout_valid), .shake_dout_ready(parse_k_dout_ready),
        .ram_we_a0(parse_ram_we_a0), .ram_we_a1(parse_ram_we_a1),
        .ram_addr(parse_ram_addr), 
        .ram_a0_din(parse_ram_a0_din), .ram_a1_din(parse_ram_a1_din)
    );

    // 5. Poly Pointwise Top
    reg         pw_start;
    wire        pw_done;
    wire        pw_host_sel;
    wire        pw_host_we;
    wire [7:0]  pw_host_addr;
    wire [15:0] pw_host_din;
    wire [15:0] pw_host_dout;

    generate
        if (HAS_INTERNAL_POLY) begin : gen_int_pw
            poly_pointwise_top u_pw (
                .clk(clk), .rst_n(rst_n), .start(pw_start), .done(pw_done),
                .host_sel(pw_host_sel), .host_we(pw_host_we), .host_addr(pw_host_addr),
                .host_din(pw_host_din), .host_dout(pw_host_dout)
            );
            assign ext_pw_start     = 1'b0;
            assign ext_pw_host_sel  = 1'b0;
            assign ext_pw_host_we   = 1'b0;
            assign ext_pw_host_addr = 8'd0;
            assign ext_pw_host_din  = 16'd0;
        end else begin : gen_ext_pw
            assign ext_pw_start     = pw_start;
            assign ext_pw_host_sel  = pw_host_sel;
            assign ext_pw_host_we   = pw_host_we;
            assign ext_pw_host_addr = pw_host_addr;
            assign ext_pw_host_din  = pw_host_din;
            assign pw_done      = ext_pw_done;
            assign pw_host_dout = ext_pw_host_dout;
        end
    endgenerate

    // 6. Poly Add/Sub Top
    reg         add_start;
    reg         add_is_sub;
    wire        add_done;
    wire        add_host_sel;
    wire        add_host_we;
    wire [7:0]  add_host_addr;
    wire [15:0] add_host_din;
    wire [15:0] add_host_dout;

    generate
        if (HAS_INTERNAL_POLY) begin : gen_int_add
            poly_add_sub_top u_add (
                .clk(clk), .rst_n(rst_n), .start(add_start), .is_sub(add_is_sub), .done(add_done),
                .host_sel(add_host_sel), .host_we(add_host_we), .host_addr(add_host_addr),
                .host_din(add_host_din), .host_dout(add_host_dout)
            );
            assign ext_add_start     = 1'b0;
            assign ext_add_is_sub    = 1'b0;
            assign ext_add_host_sel  = 1'b0;
            assign ext_add_host_we   = 1'b0;
            assign ext_add_host_addr = 8'd0;
            assign ext_add_host_din  = 16'd0;
        end else begin : gen_ext_add
            assign ext_add_start     = add_start;
            assign ext_add_is_sub    = add_is_sub;
            assign ext_add_host_sel  = add_host_sel;
            assign ext_add_host_we   = add_host_we;
            assign ext_add_host_addr = add_host_addr;
            assign ext_add_host_din  = add_host_din;
            assign add_done      = ext_add_done;
            assign add_host_dout = ext_add_host_dout;
        end
    endgenerate

    // 7. Poly ToBytes
    reg         tb_start;
    wire        tb_done;
    wire [6:0]  tb_coeff_addr;
    wire [15:0] tb_coeff_a0;
    wire [15:0] tb_coeff_a1;
    wire        tb_byte_we;
    wire [8:0]  tb_byte_addr; // 0 to 383
    wire [7:0]  tb_byte_dout;

    poly_tobytes u_tb (
        .clk(clk), .rst_n(rst_n), .start(tb_start), .done(tb_done),
        .coeff_addr(tb_coeff_addr), .coeff_a0(tb_coeff_a0), .coeff_a1(tb_coeff_a1),
        .byte_we(tb_byte_we), .byte_addr(tb_byte_addr), .byte_dout(tb_byte_dout)
    );

    // =================================================================
    // Signal Routing & Pump Memory Interface
    // =================================================================

    wire [15:0] pump_read_data = 
        (pump_src_sel == SRC_S0) ? ram_dout_a[0] :
        (pump_src_sel == SRC_S1) ? ram_dout_a[1] :
        (pump_src_sel == SRC_S2) ? ram_dout_a[2] :
        (pump_src_sel == SRC_E0) ? ram_dout_a[3] :
        (pump_src_sel == SRC_E1) ? ram_dout_a[4] :
        (pump_src_sel == SRC_E2) ? ram_dout_a[5] :
        (pump_src_sel == SRC_AHAT) ? ram_dout_a[6] :
        (pump_src_sel == SRC_NTT) ? ntt_host_dout :
        (pump_src_sel == SRC_PW)  ? pw_host_dout :
        (pump_src_sel == SRC_ADD) ? add_host_dout : 16'd0;

    assign ntt_host_we = (state == S_PUMP && pump_dst_sel == DST_NTT && pump_we);
    assign ntt_host_addr = (state == S_PUMP && pump_src_sel == SRC_NTT) ? pump_rd_addr : pump_wr_addr;
    assign ntt_host_din = pump_read_data;

    assign pw_host_sel = (state == S_PUMP && pump_dst_sel == DST_PW_B) ? 1'b1 : 1'b0;
    assign pw_host_we = (state == S_PUMP && (pump_dst_sel == DST_PW_A || pump_dst_sel == DST_PW_B) && pump_we);
    assign pw_host_addr = (state == S_PUMP && pump_src_sel == SRC_PW)  ? pump_rd_addr : pump_wr_addr;
    assign pw_host_din = pump_read_data;

    assign add_host_sel = (state == S_PUMP && pump_dst_sel == DST_ADD_B) ? 1'b1 : 1'b0;
    assign add_host_we = (state == S_PUMP && (pump_dst_sel == DST_ADD_A || pump_dst_sel == DST_ADD_B) && pump_we);
    assign add_host_addr = (state == S_PUMP && pump_src_sel == SRC_ADD) ? pump_rd_addr : pump_wr_addr;
    assign add_host_din = pump_read_data;

    integer idx;
    always @(*) begin
        for (idx=0; idx<7; idx=idx+1) begin
            ram_addr_a[idx] = 8'd0;
            ram_addr_b[idx] = 8'd0;
            ram_din_a[idx]  = 16'd0;
            ram_din_b[idx]  = 16'd0;
            ram_we_a[idx]   = 1'b0;
            ram_we_b[idx]   = 1'b0;
        end
        
        // Pump logic override
        if (state == S_PUMP) begin
            // Destination (Write)
            if (pump_dst_sel < 7) begin
                ram_addr_a[pump_dst_sel] = pump_wr_addr;
                ram_din_a[pump_dst_sel]  = pump_read_data;
                ram_we_a[pump_dst_sel]   = pump_we;
            end
            // Source (Read)
            if (pump_src_sel < 7) begin
                ram_addr_a[pump_src_sel] = pump_rd_addr;
            end
        end
        
        // CBD write override
        else if (state == S_CBD || state == S_CBD_WAIT) begin
            if (i_idx < 3) begin
                ram_addr_a[i_idx] = {cbd_ram_addr, 1'b0};
                ram_addr_b[i_idx] = {cbd_ram_addr, 1'b1};
                ram_din_a[i_idx]  = cbd_ram_a0_din;
                ram_din_b[i_idx]  = cbd_ram_a1_din;
                ram_we_a[i_idx]   = cbd_ram_we;
                ram_we_b[i_idx]   = cbd_ram_we;
            end else begin
                ram_addr_a[i_idx] = {cbd_ram_addr, 1'b0};
                ram_addr_b[i_idx] = {cbd_ram_addr, 1'b1};
                ram_din_a[i_idx]  = cbd_ram_a0_din;
                ram_din_b[i_idx]  = cbd_ram_a1_din;
                ram_we_a[i_idx]   = cbd_ram_we;
                ram_we_b[i_idx]   = cbd_ram_we;
            end
        end
        
        // P5-safe-4: prime first A_hat read on parse_done cycle before entering S_PUMP.
        else if (state == S_XOF_WAIT && parse_done) begin
            ram_addr_a[6] = 8'd0;
        end

        // Parse inline write override (Target: 6 = A_hat_buf)
        else if (state == S_XOF_A || state == S_XOF_PARSE_START || (state == S_XOF_WAIT && !parse_done)) begin
            ram_addr_a[6] = {parse_ram_addr, 1'b0};
            ram_addr_b[6] = {parse_ram_addr, 1'b1};
            ram_din_a[6]  = parse_ram_a0_din;
            ram_din_b[6]  = parse_ram_a1_din;
            ram_we_a[6]   = parse_ram_we_a0;
            ram_we_b[6]   = parse_ram_we_a1;
        end
        
        // ToBytes read override
        else if (state == S_DUMP_PK || state == S_DUMP_PK_WAIT) begin
            ram_addr_a[6] = {tb_coeff_addr, 1'b0};
            ram_addr_b[6] = {tb_coeff_addr, 1'b1};
        end
        else if (state == S_PACK_SK_SHAT || state == S_PACK_SK_SHAT_WAIT) begin
            ram_addr_a[i_idx] = {tb_coeff_addr, 1'b0};
            ram_addr_b[i_idx] = {tb_coeff_addr, 1'b1};
        end
    end

    assign tb_coeff_a0 = (state == S_DUMP_PK || state == S_DUMP_PK_WAIT) ? ram_dout_a[6] : ram_dout_a[i_idx];
    assign tb_coeff_a1 = (state == S_DUMP_PK || state == S_DUMP_PK_WAIT) ? ram_dout_b[6] : ram_dout_b[i_idx];

    // PK and SK Routing
    assign pk_we = (state == S_DUMP_PK_WAIT) ? tb_byte_we :
                   (state == S_PACK_PK && var_k < 32) ? 1'b1 : 1'b0;

    assign pk_addr = (state == S_DUMP_PK_WAIT) ? tb_byte_addr + {1'b0, i_idx, 8'd0} + {2'b0, i_idx, 7'd0} :
                     (state == S_PACK_PK)      ? 11'd1152 + var_k[10:0] : 11'd0;

    assign pk_dout = (state == S_DUMP_PK_WAIT) ? tb_byte_dout : 
                     (state == S_PACK_PK)      ? rho_reg[var_k[4:0]] : 8'd0;

    assign sk_we = (state == S_PACK_SK_SHAT_WAIT) ? tb_byte_we :
                   (state == S_PACK_SK_PK_WRITE) ? 1'b1 :
                   (state == S_PACK_SK_HPK && var_k < 32)   ? 1'b1 :
                   (state == S_PACK_SK_Z   && var_k < 32)   ? 1'b1 : 1'b0;

    assign sk_addr = (state == S_PACK_SK_SHAT_WAIT) ? {1'b0, tb_byte_addr} + {2'b0, i_idx, 8'd0} + {3'b0, i_idx, 7'd0} :
                     (state == S_PACK_SK_PK_WRITE)  ? 12'd1152 + var_k :
                     (state == S_PACK_SK_HPK)       ? 12'd2336 + var_k :
                     (state == S_PACK_SK_Z)         ? 12'd2368 + var_k : 12'd0;

    assign sk_dout = (state == S_PACK_SK_SHAT_WAIT) ? tb_byte_dout :
                     (state == S_PACK_SK_PK_WRITE)  ? pk_buf_rd_data :
                     (state == S_PACK_SK_HPK)       ? h_pk_reg[var_k[4:0]] :
                     (state == S_PACK_SK_Z)         ? seed_z_byte : 8'd0;

    // Helper to reduce duplicated pump-launch boilerplate.
    task launch_pump;
        input [3:0] src_i;
        input [3:0] dst_i;
        input [5:0] ret_state_i;
        input       kick_ntt_i;
        begin
            pump_src_sel <= src_i;
            pump_dst_sel <= dst_i;
            pump_ret_state <= ret_state_i;
            pump_cnt <= 1;
            pump_we <= 0;
            pump_rd_addr <= 8'd0;
            pump_wr_addr <= 8'hFF;
            pump_len <= 8'd255;
            pump_op_kick_ntt <= kick_ntt_i;
        end
    endtask

    task launch_keccak;
        input [1:0] h_type;
        input [5:0] target_state;
        begin
            init_keccak <= 1;
            hash_type   <= h_type;
            var_k       <= 0;
            state       <= target_state;
            // R-new-A Phase E2: lane absorb only used by SHA3-256 H(ek) of
            // pk_buf (1184B = 148 lanes). G/PRF/XOF stay byte mode because
            // their inputs are short or non-multiple-of-8.
            absorb_lane_mode_reg <= (h_type == 2'b10);
        end
    endtask

    // Pulse poly_tobytes start and jump to wait state.
    task kick_tobytes_wait;
        input [5:0] target_state;
        begin
            tb_start <= 1;
            state <= target_state;
        end
    endtask

    // Pulse add core start (add mode) and jump to add wait state.
    task kick_add_wait;
        begin
            add_start <= 1;
            add_is_sub <= 0;
            state <= S_RUN_ADD_WAIT;
        end
    endtask

    // Prime first pk_buf read and jump to PK-pack wait state.
    task prime_pkbuf_read0_wait;
        begin
            pk_buf_rd_addr <= 11'd0;
            pk_buf_rd_en <= 1;
            state <= S_PACK_SK_PK_WAIT;
        end
    endtask

    // Generic helper for 32-byte pack loops with defensive out-of-range fallback.
    task pack32_advance_or_goto;
        input [5:0] target_state;
        input       clr_var_on_jump;
        begin
            if (var_k == 31) begin
                state <= target_state;
                if (clr_var_on_jump) begin
                    var_k <= 0;
                end
            end else if (var_k < 31) begin
                var_k <= var_k + 1;
            end else begin
                state <= target_state;
                if (clr_var_on_jump) begin
                    var_k <= 0;
                end
            end
        end
    endtask

    // =================================================================
    // Main Control FSM
    // =================================================================
    // i_clr_buf removed (was only used by the soft-clear for-loop, now gone).
    always @(posedge clk) begin
        if (!rst_n) begin
            state                 <= S_IDLE;
            done                  <= 0;
            init_keccak           <= 0;
            finalize_keccak       <= 0;
            hash_type             <= 0;
            k_din                 <= 0;
            k_din_valid           <= 0;
            fsm_k_dout_ready      <= 0;
            // R-new-A Phase E2
            absorb_lane_mode_reg  <= 0;
            lane_din_valid_reg    <= 0;
            pk_buf_rd_byte_pos_d1 <= 0;
            
            cbd_start   <= 0;
            ntt_start   <= 0;
            parse_start <= 0;
            pw_start    <= 0;
            add_start   <= 0;
            tb_start    <= 0;
            add_is_sub  <= 0;
            
            i_idx <= 0;
            j_idx <= 0;
            var_k <= 0;
            
            pump_rd_addr <= 0;
            pump_wr_addr <= 0;
            pump_we      <= 0;
            pump_cnt     <= 0;
            pump_src_sel <= 0;
            pump_dst_sel <= 0;
            pump_ret_state <= 0;
            pump_len <= 0;
            pump_op_kick_ntt <= 0;
            pk_buf_rd_addr <= 0;
            pk_buf_rd_en <= 0;
        end else begin
            // Default pulse signals
            init_keccak     <= 0;
            finalize_keccak <= 0;
            k_din_valid     <= 0;
            // R-new-A Phase E2
            lane_din_valid_reg <= 0;
            // Latch byte position 1 cycle after rd_en for byte-mux read.
            if (pk_buf_rd_en) pk_buf_rd_byte_pos_d1 <= pk_buf_rd_addr[2:0];
            cbd_start       <= 0;
            ntt_start       <= 0;
            parse_start     <= 0;
            pw_start        <= 0;
            add_start       <= 0;
            tb_start        <= 0;

            case (state)
                S_IDLE: begin
                    done <= 0;
                    if (start) begin
                        // Step R5: soft-clear of rho_reg/sigma_reg/h_pk_reg
                        // removed. The previous "first pk replay" silicon bug
                        // root cause was Synth's FF-array set/reset-priority
                        // ambiguity. Now that the arrays carry the
                        // (* ram_style = "distributed" *) hint they synthesize
                        // as deterministic LUTRAM cells; SHAKE-512 fully
                        // populates rho/sigma (var_k 0..63) and the H-pk hash
                        // path fully populates h_pk_reg before any read, so
                        // stale residual is overwritten before use — same
                        // pattern as the Step 1 prf_buf cleanup.
                        // prf_buf clear was already removed — moved to
                        // dedicated BRAM write block.
                        prf_word_idx <= 4'd0;
                        prf_byte_idx <= 3'd0;
                        prf_shift    <= 64'd0;
                        i_idx        <= 3'd0;
                        j_idx        <= 3'd0;

                        launch_keccak(2'b11, S_HASH_G); // SHA3-512
                    end
                end

                S_HASH_G: begin
                    if (k_din_ready) begin
                        k_din_valid <= 1;
                        if (var_k < 32) begin
                            k_din <= seed_d_byte;
                            var_k <= var_k + 1;
                        end else begin // var_k == 32
                            k_din <= 8'd3; // index k=3 for FIPS 203 ML-KEM-768
                            var_k <= 0;
                            state <= S_HASH_G_FINAL;
                        end
                    end
                end

                S_HASH_G_FINAL: begin
                    finalize_keccak <= 1;
                    state <= S_HASH_G_WAIT;
                    end

                S_HASH_G_WAIT: begin
                    fsm_k_dout_ready <= 1;
                    if (k_dout_valid) begin
                        if (var_k < 32) begin
                            rho_reg[var_k[4:0]] <= k_dout;
                        end else begin
                            sigma_reg[var_k[4:0]] <= k_dout;
                        end
                        
                        var_k <= var_k + 1;
                        if (var_k == 63) begin
                            fsm_k_dout_ready <= 0;
                            state <= S_GEN_NOISE_INIT;
                            i_idx <= 0;
                        end
                    end
                end

                // ================== Noise Generation Loop (i=0..5) ==================
                S_GEN_NOISE_INIT: begin
                    if (i_idx == 6) begin
                        // P6-safe-1: enter first matmul row and jump to XOF directly after pump.
                        i_idx <= 0;
                        launch_pump(SRC_E0, DST_ADD_A, S_XOF_A, 1'b0); // e_hat[0] -> accumulator
                        j_idx <= 0;
                        state <= S_PUMP;
                    end else begin
                        launch_keccak(2'b01, S_PRF_SHAKE256); // SHAKE256
                    end
                end

                S_PRF_SHAKE256: begin
                    if (k_din_ready) begin
                        k_din_valid <= 1;
                        if (var_k < 32) begin
                            k_din <= sigma_reg[var_k[4:0]];
                            var_k <= var_k + 1;
                        end else begin
                            k_din <= {5'd0, i_idx};
                            var_k <= 0;
                            state <= S_PRF_FINAL;
                        end
                    end
                end

                S_PRF_FINAL: begin
                    finalize_keccak <= 1;
                    prf_word_idx <= 0;
                    prf_byte_idx <= 0;
                    state <= S_PRF_WAIT;
                end


                S_PRF_WAIT: begin
                    // prf_buf write moved to dedicated single-port BRAM block
                    // above. FSM here only updates indices/shift/state.
                    fsm_k_dout_ready <= 1;
                    if (k_dout_valid) begin
                        prf_shift <= {k_dout, prf_shift[63:8]};
                        if (prf_byte_idx == 7) begin
                            prf_word_idx <= prf_word_idx + 1;
                            prf_byte_idx <= 0;
                            if (prf_word_idx == 15) begin
                                fsm_k_dout_ready <= 0;
                                // P5-safe-3: fold S_CBD hop, pulse start directly.
                                cbd_start <= 1;
                                state <= S_CBD_WAIT;
                            end
                        end else begin
                            prf_byte_idx <= prf_byte_idx + 1;
                        end
                    end
                end

                S_CBD: begin
                    cbd_start <= 1;
                    state <= S_CBD_WAIT;
                end

                S_CBD_WAIT: begin
                    if (cbd_done) begin
                        // Direct pump launch (P4.3): descriptor state removed
                        launch_pump((i_idx < 3) ? (SRC_S0 + i_idx) : (SRC_E0 + (i_idx - 3)),
                                    DST_NTT, S_RUN_NTT, 1'b1);
                        state <= S_PUMP;
                    end
                end

                S_RUN_NTT: begin
                    ntt_start <= 1;
                    state <= S_PUMP_NTT_TO_S;
                end

                S_PUMP_NTT_TO_S: begin
                    if (ntt_done) begin
                        // Direct pump launch (P4.3): descriptor state removed
                        launch_pump(SRC_NTT, (i_idx < 3) ? (DST_S0 + i_idx) : (DST_E0 + (i_idx - 3)),
                                    S_GEN_NOISE_INIT, 1'b0);
                        state <= S_PUMP;

                        // Because state logic evaluated at end of pump returns to ret_state, we increment i_idx early
                        i_idx <= i_idx + 1;
                    end
                end

                // ================== Matrix Vector MultiLoop (i=0..2, j=0..2) ==================
                S_MAT_MUL_INIT: begin
                    if (i_idx == 3) begin
                        state <= S_PACK_PK;
                        var_k <= 0;
                    end else begin
                        // Direct pump launch (P4.3): descriptor state removed
                        launch_pump(SRC_E0 + i_idx, DST_ADD_A, S_MAT_MUL_J_INIT, 1'b0); // Init acc with e_hat[i]
                        state <= S_PUMP;
                        j_idx <= 0;
                    end
                end

                S_MAT_MUL_J_INIT: begin
                    if (j_idx == 3) begin
                        // End of row dot product, dump `add_sub.RAM_A` to A_hat_buf (acting as pk_buf)
                        // Direct pump launch (P4.3): descriptor state removed
                        launch_pump(SRC_ADD, DST_AHAT, S_DUMP_PK, 1'b0);
                        state <= S_PUMP;
                    end else begin
                        launch_keccak(2'b00, S_XOF_A); // SHAKE128
                    end
                end

                S_XOF_A: begin
                    if (k_din_ready) begin
                        k_din_valid <= 1;
                        if (var_k < 32) begin
                            k_din <= rho_reg[var_k[4:0]];
                            var_k <= var_k + 1;
                        end else if (var_k == 32) begin
                            k_din <= {5'd0, j_idx}; // j is pushed first
                            var_k <= var_k + 1;
                        end else begin
                            k_din <= {5'd0, i_idx}; // i is pushed second
                            state <= S_XOF_FINAL;
                        end
                    end
                end

                S_XOF_FINAL: begin
                    finalize_keccak <= 1;
                    state <= S_XOF_PARSE_START;
                end

                S_XOF_PARSE_START: begin
                    parse_start <= 1;
                    state <= S_XOF_WAIT;
                end

                S_XOF_WAIT: begin
                    // poly_parse_inline_top controls SHAKE stream directly
                    if (parse_done) begin
                        // P5-safe-4: launch A_hat->PW pump directly when parse completes.
                        launch_pump(SRC_AHAT, DST_PW_A, S_PUMP_S_TO_PW, 1'b0);
                        state <= S_PUMP;
                    end
                end

                S_PUMP_S_TO_PW: begin
                    // Direct pump launch (P4.3): descriptor state removed
                    launch_pump(SRC_S0 + j_idx, DST_PW_B, S_RUN_PW, 1'b0); // s_hat[j] into RAM_B
                    state <= S_PUMP;
                end

                S_RUN_PW: begin
                    pw_start <= 1;
                    state <= S_PUMP_PW_TO_ADD;
                end

                S_PUMP_PW_TO_ADD: begin
                    if (pw_done) begin
                        // Direct pump launch (P4.3): descriptor state removed
                        launch_pump(SRC_PW, DST_ADD_B, S_RUN_ADD, 1'b0);
                        state <= S_PUMP;
                    end
                end

                S_RUN_ADD: begin
                    kick_add_wait;
                end
                
                S_RUN_ADD_WAIT: begin
                    if (add_done) begin
                        // P5-safe-6: fold terminal j-loop hop (j=2 -> dump) directly.
                        if (j_idx == 2) begin
                            // End of row dot product, dump add result to A_hat buffer.
                            launch_pump(SRC_ADD, DST_AHAT, S_DUMP_PK, 1'b0);
                            j_idx <= j_idx + 1;
                            state <= S_PUMP;
                        end else begin
                            // P6-safe-1: skip S_MAT_MUL_J_INIT hop on hot path.
                            j_idx <= j_idx + 1;
                            launch_keccak(2'b00, S_XOF_A); // SHAKE128
                        end
                    end
                end

                S_DUMP_PK: begin
                    kick_tobytes_wait(S_DUMP_PK_WAIT);
                end

                S_DUMP_PK_WAIT: begin
                    if (tb_done) begin
                        // P5-safe-6: fold final i-loop terminal hop (i=2 -> pack) directly.
                        if (i_idx == 2) begin
                            i_idx <= i_idx + 1;
                            var_k <= 0;
                            state <= S_PACK_PK;
                        end else begin
                            // P6-safe-1: enter next matmul row and jump to XOF directly after pump.
                            launch_pump(SRC_E0 + i_idx + 1'b1, DST_ADD_A, S_XOF_A, 1'b0);
                            i_idx <= i_idx + 1;
                            j_idx <= 0;
                            state <= S_PUMP;
                        end
                    end
                end

                // ================== Pack Outputs ==================
                S_PACK_PK: begin
                    // P5-safe-5: fold terminal loop bubble (transition on last byte).
                    if (var_k == 31) begin
                        launch_keccak(2'b10, S_HASH_H_PK); // SHA3-256
                    end else if (var_k < 31) begin
                        var_k <= var_k + 1;
                    end else begin
                        // Defensive recovery if var_k is out of expected range.
                        launch_keccak(2'b10, S_HASH_H_PK); // SHA3-256
                    end
                end

                // R-new-A Phase E2: lane absorb path for H(ek) — 1184 bytes
                // = 148 lanes, ~3 cyc/lane × 148 + ~9 perm × 24 ≈ 660 cyc
                // total vs byte-mode ~3552 cyc, saves ~2900 cyc per KeyGen.
                S_HASH_H_PK: begin
                    if (var_k < 148) begin
                        // Lane index = var_k[7:0]; byte addr = var_k*8
                        pk_buf_rd_addr <= {var_k[7:0], 3'd0};
                        pk_buf_rd_en <= 1;
                        state <= S_HASH_H_PK_WAIT;
                    end else begin
                        finalize_keccak <= 1;
                        var_k <= 0;
                        state <= S_HASH_H_WAIT;
                    end
                end

                S_HASH_H_PK_WAIT: begin
                    // BRAM 1-cycle sync-read latency. lane_din will be valid
                    // at next posedge.
                    state <= S_HASH_H_PK_SEND;
                end

                S_HASH_H_PK_SEND: begin
                    // Phase E1 handshake fix: check valid_reg && ready_w.
                    // First cycle of SEND has valid_reg=0 (just being asserted),
                    // ready_w may be 1 (sponge in ABSORB_LANE) — without the
                    // valid gate, FSM would falsely advance without the actual
                    // sponge XOR.
                    lane_din_valid_reg <= 1'b1;
                    if (lane_din_valid_reg && lane_din_ready_w) begin
                        lane_din_valid_reg <= 1'b0;
                        var_k <= var_k + 1;
                        state <= S_HASH_H_PK;
                    end
                end

                S_HASH_H_WAIT: begin
                    fsm_k_dout_ready <= 1;
                    if (k_dout_valid) begin
                        h_pk_reg[var_k[4:0]] <= k_dout;
                        if (var_k == 31) begin
                            fsm_k_dout_ready <= 0;
                            i_idx <= 0;
                            // P6-safe-2: kick first SHAT->SK pack immediately (skip one control hop).
                            kick_tobytes_wait(S_PACK_SK_SHAT_WAIT);
                        end else begin
                            var_k <= var_k + 1;
                        end
                    end
                end

                S_PACK_SK_SHAT: begin
                    if (i_idx == 3) begin
                        state <= S_PACK_SK_PK;
                        var_k <= 0;
                    end else begin
                        kick_tobytes_wait(S_PACK_SK_SHAT_WAIT);
                    end
                end

                S_PACK_SK_SHAT_WAIT: begin
                    if (tb_done) begin
                        // P6-safe-3: fold terminal shat->pack_pk control hop.
                        if (i_idx == 2) begin
                            i_idx <= i_idx + 1;
                            var_k <= 0;
                            prime_pkbuf_read0_wait;
                        end else begin
                            // P6-safe-4: fold SHAT relaunch hop for i=0,1.
                            i_idx <= i_idx + 1;
                            kick_tobytes_wait(S_PACK_SK_SHAT_WAIT);
                        end
                    end
                end

                S_PACK_SK_PK: begin
                    // Defensive fallback: re-prime if this state is re-entered unexpectedly.
                    if (var_k != 0) begin
                        var_k <= 0;
                    end
                    prime_pkbuf_read0_wait;
                end

                S_PACK_SK_PK_WAIT: begin
                    // Consume one read-latency cycle for pk_buf.
                    state <= S_PACK_SK_PK_WRITE;
                end

                S_PACK_SK_PK_WRITE: begin
                    if (var_k == 1183) begin
                        pk_buf_rd_en <= 0;
                        var_k <= 0;
                        state <= S_PACK_SK_HPK;
                    end else begin
                        // Issue next read, then wait one cycle before next write to
                        // align with synchronous BRAM read latency.
                        var_k <= var_k + 1;
                        pk_buf_rd_addr <= var_k[10:0] + 11'd1;
                        pk_buf_rd_en <= 1;
                        state <= S_PACK_SK_PK_WAIT;
                    end
                end

                S_PACK_SK_HPK: begin
                    // P5-safe-5: fold terminal loop bubble (transition on last byte).
                    pack32_advance_or_goto(S_PACK_SK_Z, 1'b1);
                end

                S_PACK_SK_Z: begin
                    // P5-safe-5: fold terminal loop bubble (transition on last byte).
                    pack32_advance_or_goto(S_DONE, 1'b0);
                end

                // ================== Core Pump Engine (257 cycles) ==================
                S_PUMP: begin
                    if (pump_cnt == ({1'b0, pump_len} + 9'd2)) begin
                        pump_we <= 0;
                        pump_cnt <= 0;
                        if (pump_op_kick_ntt) ntt_start <= 1;
                        if (pump_ret_state == S_RUN_NTT) begin
                            // P4.4-b: fold RUN_NTT hop by kicking NTT immediately on pump done.
                            ntt_start <= 1;
                            state <= S_PUMP_NTT_TO_S;
                        end else if (pump_ret_state == S_RUN_PW) begin
                            // P4.4-b: fold RUN_PW hop by kicking PW immediately on pump done.
                            pw_start <= 1;
                            state <= S_PUMP_PW_TO_ADD;
                        end else if (pump_ret_state == S_RUN_ADD) begin
                            // P4.4-b: fold RUN_ADD hop by kicking add immediately on pump done.
                            kick_add_wait;
                        end else if (pump_ret_state == S_DUMP_PK) begin
                            // P5-safe: fold DUMP_PK hop by kicking ToBytes immediately on pump done.
                            kick_tobytes_wait(S_DUMP_PK_WAIT);
                        end else if (pump_ret_state == S_XOF_A) begin
                            // P6-safe-1: kick SHAKE128 directly on pump completion.
                            launch_keccak(2'b00, S_XOF_A); // SHAKE128
                        end else begin
                            state <= pump_ret_state;
                        end
                    end else begin
                        pump_rd_addr <= pump_rd_addr + 1'b1;
                        pump_wr_addr <= pump_wr_addr + 1'b1;
                        pump_we      <= 1'b1;
                        pump_cnt     <= pump_cnt + 1'b1;
                    end
                end

                S_DONE: begin
                    done  <= 1;
                    state <= S_IDLE;  // return to IDLE so the next start can re-trigger
                end

                default: state <= S_IDLE;
            endcase
        end
    end
endmodule
