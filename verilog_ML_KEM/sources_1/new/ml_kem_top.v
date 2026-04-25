`timescale 1ns / 1ps

module ml_kem_top #
(
    parameter integer C_S_AXI_ADDR_WIDTH = 8,
    parameter integer C_S_AXI_DATA_WIDTH = 32,
    parameter integer C_M_AXI_ADDR_WIDTH = 32,
    parameter integer C_M_AXI_DATA_WIDTH = 32,
    parameter integer BYPASS_CRYPTO = 0
)
(
    input  wire                               clk,
    input  wire                               rst_n,

    input  wire [C_S_AXI_ADDR_WIDTH-1:0]      s_axi_awaddr,
    input  wire                               s_axi_awvalid,
    output wire                               s_axi_awready,
    input  wire [C_S_AXI_DATA_WIDTH-1:0]      s_axi_wdata,
    input  wire [(C_S_AXI_DATA_WIDTH/8)-1:0]  s_axi_wstrb,
    input  wire                               s_axi_wvalid,
    output wire                               s_axi_wready,
    output wire [1:0]                         s_axi_bresp,
    output wire                               s_axi_bvalid,
    input  wire                               s_axi_bready,
    input  wire [C_S_AXI_ADDR_WIDTH-1:0]      s_axi_araddr,
    input  wire                               s_axi_arvalid,
    output wire                               s_axi_arready,
    output wire [C_S_AXI_DATA_WIDTH-1:0]      s_axi_rdata,
    output wire [1:0]                         s_axi_rresp,
    output wire                               s_axi_rvalid,
    input  wire                               s_axi_rready,

    output reg  [C_M_AXI_ADDR_WIDTH-1:0]      m_axi_awaddr,
    output reg  [7:0]                         m_axi_awlen,
    output reg  [2:0]                         m_axi_awsize,
    output reg  [1:0]                         m_axi_awburst,
    output reg                                m_axi_awvalid,
    input  wire                               m_axi_awready,

    output reg  [C_M_AXI_DATA_WIDTH-1:0]      m_axi_wdata,
    output reg  [(C_M_AXI_DATA_WIDTH/8)-1:0]  m_axi_wstrb,
    output reg                                m_axi_wlast,
    output reg                                m_axi_wvalid,
    input  wire                               m_axi_wready,

    input  wire [1:0]                         m_axi_bresp,
    input  wire                               m_axi_bvalid,
    output reg                                m_axi_bready,

    output reg  [C_M_AXI_ADDR_WIDTH-1:0]      m_axi_araddr,
    output reg  [7:0]                         m_axi_arlen,
    output reg  [2:0]                         m_axi_arsize,
    output reg  [1:0]                         m_axi_arburst,
    output reg                                m_axi_arvalid,
    input  wire                               m_axi_arready,

    input  wire [C_M_AXI_DATA_WIDTH-1:0]      m_axi_rdata,
    input  wire [1:0]                         m_axi_rresp,
    input  wire                               m_axi_rlast,
    input  wire                               m_axi_rvalid,
    output reg                                m_axi_rready
);

    localparam [1:0] OP_KEYGEN = 2'd0;
    localparam [1:0] OP_ENCAPS = 2'd1;
    localparam [1:0] OP_DECAPS = 2'd2;

    localparam [3:0] BUF_PK = 4'd0;
    localparam [3:0] BUF_SK = 4'd1;
    localparam [3:0] BUF_CT = 4'd2;
    localparam [3:0] BUF_M  = 4'd3;
    localparam [3:0] BUF_DK = 4'd4;
    localparam [3:0] BUF_SS = 4'd5;

    localparam [7:0] S_IDLE                 = 8'd0;
    localparam [7:0] S_KEYGEN_START         = 8'd1;
    localparam [7:0] S_KEYGEN_WAIT          = 8'd2;
    localparam [7:0] S_ENCAPS_READ_PK       = 8'd3;
    localparam [7:0] S_ENCAPS_READ_M        = 8'd4;
    localparam [7:0] S_ENCAPS_PRELOAD_EK_FETCH = 8'd5;
    localparam [7:0] S_ENCAPS_PRELOAD_M     = 8'd6;
    localparam [7:0] S_ENCAPS_START         = 8'd7;
    localparam [7:0] S_ENCAPS_WAIT          = 8'd8;
    localparam [7:0] S_DECAPS_READ_DK       = 8'd9;
    localparam [7:0] S_DECAPS_READ_CT       = 8'd10;
    localparam [7:0] S_DECAPS_PRELOAD_DK_FETCH = 8'd11;
    localparam [7:0] S_DECAPS_PRELOAD_CT_FETCH = 8'd12;
    localparam [7:0] S_DECAPS_START         = 8'd13;
    localparam [7:0] S_DECAPS_WAIT          = 8'd14;
    localparam [7:0] S_CAPTURE_SS           = 8'd15;
    localparam [7:0] S_WRITE_PK             = 8'd16;
    localparam [7:0] S_WRITE_SK             = 8'd17;
    localparam [7:0] S_WRITE_CT             = 8'd18;
    localparam [7:0] S_WRITE_SS             = 8'd19;
    localparam [7:0] S_DONE                 = 8'd20;
    localparam [7:0] S_ERR                  = 8'd21;
    localparam [7:0] S_MM_RD_AR             = 8'd22;
    localparam [7:0] S_MM_RD_R              = 8'd23;
    localparam [7:0] S_MM_WR_AW_W           = 8'd24;
    localparam [7:0] S_MM_WR_B              = 8'd25;
    localparam [7:0] S_BYPASS_WAIT          = 8'd26;
    localparam [7:0] S_MM_WR_W              = 8'd27;
    localparam [7:0] S_MM_WR_FETCH          = 8'd28;
    localparam [7:0] S_ENCAPS_PRELOAD_EK_SEND = 8'd29;
    localparam [7:0] S_DECAPS_PRELOAD_DK_SEND = 8'd30;
    localparam [7:0] S_DECAPS_PRELOAD_CT_SEND = 8'd31;
    localparam [7:0] S_BYPASS_FILL_PK       = 8'd32;
    localparam [7:0] S_BYPASS_FILL_SK       = 8'd33;
    localparam [7:0] S_BYPASS_FILL_CT       = 8'd34;

    reg [7:0] state;
    reg [7:0] ret_state_after_mm;

    reg        status_done;
    reg        status_error;
    reg [31:0] cycles_count;
    wire       status_idle = (state == S_IDLE);

    wire       cfg_start_pulse;
    wire [1:0] cfg_op_sel;
    wire [255:0] cfg_seed_d;
    wire [255:0] cfg_seed_z;
    wire [31:0] cfg_pk_addr;
    wire [31:0] cfg_sk_addr;
    wire [31:0] cfg_ct_addr;
    wire [31:0] cfg_ss_addr;
    wire [31:0] cfg_m_addr;

    reg [1:0] op_sel_latched;

    reg [11:0] byte_idx;
    reg [5:0] bypass_wait_cnt;

    reg [11:0] mm_word_idx;
    reg [11:0] mm_word_total;
    reg [31:0] mm_base_addr;
    reg [3:0]  mm_buf_sel;

    // ========================================================================
    // Large transfer buffers: 32-bit word BRAMs with byte-strobe writes.
    // Each BRAM serves (a) AXI 32-bit word transfers to/from DDR and (b) byte
    // writes/reads from crypto cores via byte strobes / byte-lane mux.
    // pk/ct: 1184 B / 1088 B → 296 / 272 words → 9-bit word address.
    // sk/dk: 2400 B each    → 600 words         → 10-bit word address.
    // m/ss:  32 B each, kept as reg arrays (too small to warrant a BRAM).
    // ========================================================================
    wire [3:0]  pk_wea;
    wire [8:0]  pk_waddr;
    wire [31:0] pk_wdata;
    wire        pk_rd_en;
    wire [8:0]  pk_rd_addr;
    wire [31:0] pk_rd_data;

    wire [3:0]  sk_wea;
    wire [9:0]  sk_waddr;
    wire [31:0] sk_wdata;
    wire        sk_rd_en;
    wire [9:0]  sk_rd_addr;
    wire [31:0] sk_rd_data;

    wire [3:0]  ct_wea;
    wire [8:0]  ct_waddr;
    wire [31:0] ct_wdata;
    wire        ct_rd_en;
    wire [8:0]  ct_rd_addr;
    wire [31:0] ct_rd_data;

    wire [3:0]  dk_wea;
    wire [9:0]  dk_waddr;
    wire [31:0] dk_wdata;
    wire        dk_rd_en;
    wire [9:0]  dk_rd_addr;
    wire [31:0] dk_rd_data;

    reg [7:0] m_mem  [0:31];
    reg [7:0] ss_mem [0:31];

    xpm_ram_sdp_word_bs #(.ADDR_WIDTH(9),  .DEPTH(512),  .READ_LATENCY(1)) u_pk_mem (
        .clk(clk), .wr_be(pk_wea), .wr_addr(pk_waddr), .wr_data(pk_wdata),
        .rd_en(pk_rd_en), .rd_addr(pk_rd_addr), .rd_data(pk_rd_data)
    );
    xpm_ram_sdp_word_bs #(.ADDR_WIDTH(10), .DEPTH(1024), .READ_LATENCY(1)) u_sk_mem (
        .clk(clk), .wr_be(sk_wea), .wr_addr(sk_waddr), .wr_data(sk_wdata),
        .rd_en(sk_rd_en), .rd_addr(sk_rd_addr), .rd_data(sk_rd_data)
    );
    xpm_ram_sdp_word_bs #(.ADDR_WIDTH(9),  .DEPTH(512),  .READ_LATENCY(1)) u_ct_mem (
        .clk(clk), .wr_be(ct_wea), .wr_addr(ct_waddr), .wr_data(ct_wdata),
        .rd_en(ct_rd_en), .rd_addr(ct_rd_addr), .rd_data(ct_rd_data)
    );
    xpm_ram_sdp_word_bs #(.ADDR_WIDTH(10), .DEPTH(1024), .READ_LATENCY(1)) u_dk_mem (
        .clk(clk), .wr_be(dk_wea), .wr_addr(dk_waddr), .wr_data(dk_wdata),
        .rd_en(dk_rd_en), .rd_addr(dk_rd_addr), .rd_data(dk_rd_data)
    );

    // -----------------------------------------------------------------
    // Shadow byte-addressed reg arrays — simulation-only observability
    // windows for the BRAM-backed transfer buffers. They mirror every
    // write to the BRAM write port so that testbenches can keep doing
    // `dut.pk_mem[i]`, `dut.sk_mem[i]`, etc. without knowing about the
    // internal word layout. The `SYNTHESIS` guard keeps these out of
    // Vivado synth so no LUT/FF area is spent on them.
    // -----------------------------------------------------------------
`ifndef SYNTHESIS
    reg [7:0] pk_mem [0:1183];
    reg [7:0] sk_mem [0:2399];
    reg [7:0] ct_mem [0:1087];
    reg [7:0] dk_mem [0:2399];

    always @(posedge clk) begin
        if (pk_wea[0]) pk_mem[{pk_waddr, 2'b00}] <= pk_wdata[7:0];
        if (pk_wea[1]) pk_mem[{pk_waddr, 2'b01}] <= pk_wdata[15:8];
        if (pk_wea[2]) pk_mem[{pk_waddr, 2'b10}] <= pk_wdata[23:16];
        if (pk_wea[3]) pk_mem[{pk_waddr, 2'b11}] <= pk_wdata[31:24];

        if (sk_wea[0]) sk_mem[{sk_waddr, 2'b00}] <= sk_wdata[7:0];
        if (sk_wea[1]) sk_mem[{sk_waddr, 2'b01}] <= sk_wdata[15:8];
        if (sk_wea[2]) sk_mem[{sk_waddr, 2'b10}] <= sk_wdata[23:16];
        if (sk_wea[3]) sk_mem[{sk_waddr, 2'b11}] <= sk_wdata[31:24];

        if (ct_wea[0]) ct_mem[{ct_waddr, 2'b00}] <= ct_wdata[7:0];
        if (ct_wea[1]) ct_mem[{ct_waddr, 2'b01}] <= ct_wdata[15:8];
        if (ct_wea[2]) ct_mem[{ct_waddr, 2'b10}] <= ct_wdata[23:16];
        if (ct_wea[3]) ct_mem[{ct_waddr, 2'b11}] <= ct_wdata[31:24];

        if (dk_wea[0]) dk_mem[{dk_waddr, 2'b00}] <= dk_wdata[7:0];
        if (dk_wea[1]) dk_mem[{dk_waddr, 2'b01}] <= dk_wdata[15:8];
        if (dk_wea[2]) dk_mem[{dk_waddr, 2'b10}] <= dk_wdata[23:16];
        if (dk_wea[3]) dk_mem[{dk_waddr, 2'b11}] <= dk_wdata[31:24];
    end
`endif

    reg        keygen_start;
    wire       keygen_done;
    wire       keygen_pk_we;
    wire [10:0] keygen_pk_addr;
    wire [7:0] keygen_pk_dout;
    wire       keygen_sk_we;
    wire [11:0] keygen_sk_addr;
    wire [7:0] keygen_sk_dout;

    reg        enc_start;
    reg        enc_in_we;
    reg        enc_in_sel;
    reg [10:0] enc_in_waddr;
    reg [7:0]  enc_in_wdata;
    wire       enc_busy;
    wire       enc_done;
    wire       enc_ct_we;
    wire [10:0] enc_ct_addr;
    wire [7:0] enc_ct_dout;
    wire [255:0] enc_ss_out;

    reg        dec_start;
    reg        dec_in_we;
    reg        dec_in_sel;
    reg [11:0] dec_in_waddr;
    reg [7:0]  dec_in_wdata;
    wire       dec_busy;
    wire       dec_done;
    wire [255:0] dec_ss_out;

    wire        kg_k_init;
    wire [1:0]  kg_k_hash_type;
    wire        kg_k_finalize;
    wire [7:0]  kg_k_din;
    wire        kg_k_din_valid;
    wire        kg_k_din_ready;
    wire [7:0]  kg_k_dout;
    wire        kg_k_dout_valid;
    wire        kg_k_dout_ready;

    wire        enc_k_init;
    wire [1:0]  enc_k_hash_type;
    wire        enc_k_finalize;
    wire [7:0]  enc_k_din;
    wire        enc_k_din_valid;
    wire        enc_k_din_ready;
    wire [7:0]  enc_k_dout;
    wire        enc_k_dout_valid;
    wire        enc_k_dout_ready;

    wire        dec_k_init;
    wire [1:0]  dec_k_hash_type;
    wire        dec_k_finalize;
    wire [7:0]  dec_k_din;
    wire        dec_k_din_valid;
    wire        dec_k_din_ready;
    wire [7:0]  dec_k_dout;
    wire        dec_k_dout_valid;
    wire        dec_k_dout_ready;

    wire [1:0]  k_owner = op_sel_latched;
    wire        top_k_init       = (k_owner == OP_KEYGEN) ? kg_k_init :
                                   (k_owner == OP_ENCAPS) ? enc_k_init :
                                   (k_owner == OP_DECAPS) ? dec_k_init : 1'b0;
    wire [1:0]  top_k_hash_type  = (k_owner == OP_KEYGEN) ? kg_k_hash_type :
                                   (k_owner == OP_ENCAPS) ? enc_k_hash_type :
                                   (k_owner == OP_DECAPS) ? dec_k_hash_type : 2'b00;
    wire        top_k_finalize   = (k_owner == OP_KEYGEN) ? kg_k_finalize :
                                   (k_owner == OP_ENCAPS) ? enc_k_finalize :
                                   (k_owner == OP_DECAPS) ? dec_k_finalize : 1'b0;
    wire [7:0]  top_k_din        = (k_owner == OP_KEYGEN) ? kg_k_din :
                                   (k_owner == OP_ENCAPS) ? enc_k_din :
                                   (k_owner == OP_DECAPS) ? dec_k_din : 8'd0;
    wire        top_k_din_valid  = (k_owner == OP_KEYGEN) ? kg_k_din_valid :
                                   (k_owner == OP_ENCAPS) ? enc_k_din_valid :
                                   (k_owner == OP_DECAPS) ? dec_k_din_valid : 1'b0;
    wire        top_k_dout_ready = (k_owner == OP_KEYGEN) ? kg_k_dout_ready :
                                   (k_owner == OP_ENCAPS) ? enc_k_dout_ready :
                                   (k_owner == OP_DECAPS) ? dec_k_dout_ready : 1'b0;
    wire        top_k_din_ready;
    wire [7:0]  top_k_dout;
    wire        top_k_dout_valid;

    keccak_sponge_top u_keccak (
        .clk(clk),
        .rst_n(rst_n),
        .init(top_k_init),
        .hash_type(top_k_hash_type),
        .finalize(top_k_finalize),
        .din(top_k_din),
        .din_valid(top_k_din_valid),
        .din_ready(top_k_din_ready),
        .dout(top_k_dout),
        .dout_valid(top_k_dout_valid),
        .dout_ready(top_k_dout_ready)
    );

    assign kg_k_din_ready  = (k_owner == OP_KEYGEN) ? top_k_din_ready : 1'b0;
    assign kg_k_dout       = (k_owner == OP_KEYGEN) ? top_k_dout : 8'd0;
    assign kg_k_dout_valid = (k_owner == OP_KEYGEN) ? top_k_dout_valid : 1'b0;

    assign enc_k_din_ready  = (k_owner == OP_ENCAPS) ? top_k_din_ready : 1'b0;
    assign enc_k_dout       = (k_owner == OP_ENCAPS) ? top_k_dout : 8'd0;
    assign enc_k_dout_valid = (k_owner == OP_ENCAPS) ? top_k_dout_valid : 1'b0;

    assign dec_k_din_ready  = (k_owner == OP_DECAPS) ? top_k_din_ready : 1'b0;
    assign dec_k_dout       = (k_owner == OP_DECAPS) ? top_k_dout : 8'd0;
    assign dec_k_dout_valid = (k_owner == OP_DECAPS) ? top_k_dout_valid : 1'b0;

    integer i;

    // ========================================================================
    // BRAM write-port muxing
    // Writers are time-exclusive by FSM design:
    //   pk: keygen_pk_we (KEYGEN phase), AXI-MM RDATA (ENCAPS preload read from
    //       DDR), BYPASS fill (keygen bypass).
    //   sk: keygen_sk_we (KEYGEN phase), BYPASS fill.
    //   ct: enc_ct_we (ENCAPS phase), AXI-MM RDATA (DECAPS preload), BYPASS.
    //   dk: AXI-MM RDATA only (DECAPS preload).
    // ========================================================================
    wire        pk_bw_en    = keygen_pk_we && (keygen_pk_addr < 11'd1184);
    wire [1:0]  pk_bw_lane  = keygen_pk_addr[1:0];
    wire [8:0]  pk_bw_waddr = keygen_pk_addr[10:2];

    wire        sk_bw_en    = keygen_sk_we && (keygen_sk_addr < 12'd2400);
    wire [1:0]  sk_bw_lane  = keygen_sk_addr[1:0];
    wire [9:0]  sk_bw_waddr = keygen_sk_addr[11:2];

    wire        ct_bw_en    = enc_ct_we && (enc_ct_addr < 11'd1088);
    wire [1:0]  ct_bw_lane  = enc_ct_addr[1:0];
    wire [8:0]  ct_bw_waddr = enc_ct_addr[10:2];

    wire        axi_word_we = (state == S_MM_RD_R) && m_axi_rvalid && m_axi_rready
                              && (m_axi_rresp == 2'b00);
    wire        pk_ww_en    = axi_word_we && (mm_buf_sel == BUF_PK);
    wire        sk_ww_en    = axi_word_we && (mm_buf_sel == BUF_SK);
    wire        ct_ww_en    = axi_word_we && (mm_buf_sel == BUF_CT);
    wire        dk_ww_en    = axi_word_we && (mm_buf_sel == BUF_DK);

    wire        bypass_fill_pk = (state == S_BYPASS_FILL_PK);
    wire        bypass_fill_sk = (state == S_BYPASS_FILL_SK);
    wire        bypass_fill_ct = (state == S_BYPASS_FILL_CT);

    // Bypass dummy pattern: byte[i] = i[7:0] ^ 0x5A (pk), ^0xA5 (sk), +0x11 (ct).
    wire [7:0]  pat_base    = {mm_word_idx[5:0], 2'b00};
    wire [31:0] pk_bypass_w = {(pat_base + 8'd3) ^ 8'h5A, (pat_base + 8'd2) ^ 8'h5A,
                               (pat_base + 8'd1) ^ 8'h5A,  pat_base           ^ 8'h5A};
    wire [31:0] sk_bypass_w = {(pat_base + 8'd3) ^ 8'hA5, (pat_base + 8'd2) ^ 8'hA5,
                               (pat_base + 8'd1) ^ 8'hA5,  pat_base           ^ 8'hA5};
    wire [31:0] ct_bypass_w = {(pat_base + 8'd3) + 8'h11, (pat_base + 8'd2) + 8'h11,
                               (pat_base + 8'd1) + 8'h11,  pat_base           + 8'h11};

    assign pk_wea   = pk_bw_en        ? (4'b0001 << pk_bw_lane) :
                      (pk_ww_en | bypass_fill_pk) ? 4'b1111 :
                                                    4'b0000;
    assign pk_waddr = pk_bw_en        ? pk_bw_waddr :
                                        mm_word_idx[8:0];
    assign pk_wdata = pk_bw_en        ? {4{keygen_pk_dout}} :
                      bypass_fill_pk  ? pk_bypass_w :
                                        m_axi_rdata;

    assign sk_wea   = sk_bw_en        ? (4'b0001 << sk_bw_lane) :
                      (sk_ww_en | bypass_fill_sk) ? 4'b1111 :
                                                    4'b0000;
    assign sk_waddr = sk_bw_en        ? sk_bw_waddr :
                                        mm_word_idx[9:0];
    assign sk_wdata = sk_bw_en        ? {4{keygen_sk_dout}} :
                      bypass_fill_sk  ? sk_bypass_w :
                                        m_axi_rdata;

    assign ct_wea   = ct_bw_en        ? (4'b0001 << ct_bw_lane) :
                      (ct_ww_en | bypass_fill_ct) ? 4'b1111 :
                                                    4'b0000;
    assign ct_waddr = ct_bw_en        ? ct_bw_waddr :
                                        mm_word_idx[8:0];
    assign ct_wdata = ct_bw_en        ? {4{enc_ct_dout}} :
                      bypass_fill_ct  ? ct_bypass_w :
                                        m_axi_rdata;

    assign dk_wea   = dk_ww_en ? 4'b1111 : 4'b0000;
    assign dk_waddr = mm_word_idx[9:0];
    assign dk_wdata = m_axi_rdata;

    // ========================================================================
    // BRAM read-port muxing (combinational rd_en from state so rd_data is
    // observable in the cycle after FETCH state — matches XPM READ_LATENCY=1).
    // ========================================================================
    wire preload_pk_fetch = (state == S_ENCAPS_PRELOAD_EK_FETCH);
    wire preload_dk_fetch = (state == S_DECAPS_PRELOAD_DK_FETCH);
    wire preload_ct_fetch = (state == S_DECAPS_PRELOAD_CT_FETCH);
    wire mm_wr_fetch      = (state == S_MM_WR_FETCH);

    assign pk_rd_en   = preload_pk_fetch || (mm_wr_fetch && (mm_buf_sel == BUF_PK));
    assign pk_rd_addr = preload_pk_fetch ? byte_idx[10:2] : mm_word_idx[8:0];

    assign sk_rd_en   = mm_wr_fetch && (mm_buf_sel == BUF_SK);
    assign sk_rd_addr = mm_word_idx[9:0];

    assign ct_rd_en   = preload_ct_fetch || (mm_wr_fetch && (mm_buf_sel == BUF_CT));
    assign ct_rd_addr = preload_ct_fetch ? byte_idx[10:2] : mm_word_idx[8:0];

    assign dk_rd_en   = preload_dk_fetch || (mm_wr_fetch && (mm_buf_sel == BUF_DK));
    assign dk_rd_addr = preload_dk_fetch ? byte_idx[11:2] : mm_word_idx[9:0];

    // Word source for AXI-MM write path. For BUF_M / BUF_SS we read combinatori-
    // ally from the small reg arrays; for BRAM-backed buffers we use rd_data
    // (valid 1 cycle after S_MM_WR_FETCH, which is S_MM_WR_W).
    wire [11:0] m_wi_x4 = mm_word_idx * 12'd4;
    wire [31:0] m_word  = {m_mem[m_wi_x4 + 12'd3], m_mem[m_wi_x4 + 12'd2],
                           m_mem[m_wi_x4 + 12'd1], m_mem[m_wi_x4]};
    wire [31:0] ss_word = {ss_mem[m_wi_x4 + 12'd3], ss_mem[m_wi_x4 + 12'd2],
                           ss_mem[m_wi_x4 + 12'd1], ss_mem[m_wi_x4]};

    wire [31:0] write_word_comb = (mm_buf_sel == BUF_PK) ? pk_rd_data :
                                  (mm_buf_sel == BUF_SK) ? sk_rd_data :
                                  (mm_buf_sel == BUF_CT) ? ct_rd_data :
                                  (mm_buf_sel == BUF_DK) ? dk_rd_data :
                                  (mm_buf_sel == BUF_M)  ? m_word :
                                  (mm_buf_sel == BUF_SS) ? ss_word :
                                                           32'd0;

    // Byte-lane mux for preload paths (rd_data is observable in *_SEND state).
    wire [1:0] byte_lane = byte_idx[1:0];
    wire [7:0] pk_byte_mux = (byte_lane == 2'd0) ? pk_rd_data[7:0]   :
                             (byte_lane == 2'd1) ? pk_rd_data[15:8]  :
                             (byte_lane == 2'd2) ? pk_rd_data[23:16] :
                                                   pk_rd_data[31:24];
    wire [7:0] dk_byte_mux = (byte_lane == 2'd0) ? dk_rd_data[7:0]   :
                             (byte_lane == 2'd1) ? dk_rd_data[15:8]  :
                             (byte_lane == 2'd2) ? dk_rd_data[23:16] :
                                                   dk_rd_data[31:24];
    wire [7:0] ct_byte_mux = (byte_lane == 2'd0) ? ct_rd_data[7:0]   :
                             (byte_lane == 2'd1) ? ct_rd_data[15:8]  :
                             (byte_lane == 2'd2) ? ct_rd_data[23:16] :
                                                   ct_rd_data[31:24];

    ml_kem_axi_lite_slave #(
        .C_S_AXI_ADDR_WIDTH(C_S_AXI_ADDR_WIDTH),
        .C_S_AXI_DATA_WIDTH(C_S_AXI_DATA_WIDTH)
    ) u_axi_lite (
        .aclk(clk),
        .aresetn(rst_n),
        .s_axi_awaddr(s_axi_awaddr),
        .s_axi_awvalid(s_axi_awvalid),
        .s_axi_awready(s_axi_awready),
        .s_axi_wdata(s_axi_wdata),
        .s_axi_wstrb(s_axi_wstrb),
        .s_axi_wvalid(s_axi_wvalid),
        .s_axi_wready(s_axi_wready),
        .s_axi_bresp(s_axi_bresp),
        .s_axi_bvalid(s_axi_bvalid),
        .s_axi_bready(s_axi_bready),
        .s_axi_araddr(s_axi_araddr),
        .s_axi_arvalid(s_axi_arvalid),
        .s_axi_arready(s_axi_arready),
        .s_axi_rdata(s_axi_rdata),
        .s_axi_rresp(s_axi_rresp),
        .s_axi_rvalid(s_axi_rvalid),
        .s_axi_rready(s_axi_rready),
        .status_done(status_done),
        .status_idle(status_idle),
        .status_error(status_error),
        .cycles_count(cycles_count),
        .start_pulse(cfg_start_pulse),
        .op_sel(cfg_op_sel),
        .seed_d(cfg_seed_d),
        .seed_z(cfg_seed_z),
        .pk_addr(cfg_pk_addr),
        .sk_addr(cfg_sk_addr),
        .ct_addr(cfg_ct_addr),
        .ss_addr(cfg_ss_addr),
        .m_addr(cfg_m_addr)
    );

    generate
        if (BYPASS_CRYPTO == 0) begin : g_crypto_real
            ml_kem_keygen #(
                .HAS_INTERNAL_KECCAK(0)
            ) u_keygen (
                .clk(clk),
                .rst_n(rst_n),
                .start(keygen_start),
                .done(keygen_done),
                .seed_d_in(cfg_seed_d),
                .seed_z_in(cfg_seed_z),
                .pk_we(keygen_pk_we),
                .pk_addr(keygen_pk_addr),
                .pk_dout(keygen_pk_dout),
                .sk_we(keygen_sk_we),
                .sk_addr(keygen_sk_addr),
                .sk_dout(keygen_sk_dout),
                .ext_k_init(kg_k_init),
                .ext_k_hash_type(kg_k_hash_type),
                .ext_k_finalize(kg_k_finalize),
                .ext_k_din(kg_k_din),
                .ext_k_din_valid(kg_k_din_valid),
                .ext_k_din_ready(kg_k_din_ready),
                .ext_k_dout(kg_k_dout),
                .ext_k_dout_valid(kg_k_dout_valid),
                .ext_k_dout_ready(kg_k_dout_ready)
            );

            ml_kem_encaps #(
                .HAS_INTERNAL_KECCAK(0)
            ) u_encaps (
                .clk(clk),
                .rst_n(rst_n),
                .start(enc_start),
                .busy(enc_busy),
                .done(enc_done),
                .in_we(enc_in_we),
                .in_sel(enc_in_sel),
                .in_addr(enc_in_waddr),
                .in_wdata(enc_in_wdata),
                .out_rd(1'b0),
                .out_sel(1'b0),
                .out_addr(11'd0),
                .out_rdata(),
                .out_valid(),
                .ct_we(enc_ct_we),
                .ct_addr(enc_ct_addr),
                .ct_dout(enc_ct_dout),
                .ss_out(enc_ss_out),
                .ext_k_init(enc_k_init),
                .ext_k_hash_type(enc_k_hash_type),
                .ext_k_finalize(enc_k_finalize),
                .ext_k_din(enc_k_din),
                .ext_k_din_valid(enc_k_din_valid),
                .ext_k_din_ready(enc_k_din_ready),
                .ext_k_dout(enc_k_dout),
                .ext_k_dout_valid(enc_k_dout_valid),
                .ext_k_dout_ready(enc_k_dout_ready)
            );

            ml_kem_decaps #(
                .HAS_INTERNAL_KECCAK(0)
            ) u_decaps (
                .clk(clk),
                .rst_n(rst_n),
                .start(dec_start),
                .busy(dec_busy),
                .done(dec_done),
                .in_we(dec_in_we),
                .in_sel(dec_in_sel),
                .in_addr(dec_in_waddr),
                .in_wdata(dec_in_wdata),
                .out_rd(1'b0),
                .out_addr(11'd0),
                .out_rdata(),
                .out_valid(),
                .ss_out(dec_ss_out),
                .ext_k_init(dec_k_init),
                .ext_k_hash_type(dec_k_hash_type),
                .ext_k_finalize(dec_k_finalize),
                .ext_k_din(dec_k_din),
                .ext_k_din_valid(dec_k_din_valid),
                .ext_k_din_ready(dec_k_din_ready),
                .ext_k_dout(dec_k_dout),
                .ext_k_dout_valid(dec_k_dout_valid),
                .ext_k_dout_ready(dec_k_dout_ready)
            );
        end else begin : g_crypto_bypass
            assign keygen_done   = 1'b0;
            assign keygen_pk_we  = 1'b0;
            assign keygen_pk_addr = 11'd0;
            assign keygen_pk_dout = 8'd0;
            assign keygen_sk_we   = 1'b0;
            assign keygen_sk_addr = 12'd0;
            assign keygen_sk_dout = 8'd0;
            assign enc_busy      = 1'b0;
            assign enc_done      = 1'b0;
            assign enc_ct_we     = 1'b0;
            assign enc_ct_addr   = 11'd0;
            assign enc_ct_dout   = 8'd0;
            assign enc_ss_out    = 256'd0;
            assign dec_busy      = 1'b0;
            assign dec_done      = 1'b0;
            assign dec_ss_out    = 256'd0;
            assign kg_k_init       = 1'b0;
            assign kg_k_hash_type  = 2'b00;
            assign kg_k_finalize   = 1'b0;
            assign kg_k_din        = 8'd0;
            assign kg_k_din_valid  = 1'b0;
            assign kg_k_dout_ready = 1'b0;
            assign enc_k_init       = 1'b0;
            assign enc_k_hash_type  = 2'b00;
            assign enc_k_finalize   = 1'b0;
            assign enc_k_din        = 8'd0;
            assign enc_k_din_valid  = 1'b0;
            assign enc_k_dout_ready = 1'b0;
            assign dec_k_init       = 1'b0;
            assign dec_k_hash_type  = 2'b00;
            assign dec_k_finalize   = 1'b0;
            assign dec_k_din        = 8'd0;
            assign dec_k_din_valid  = 1'b0;
            assign dec_k_dout_ready = 1'b0;
        end
    endgenerate

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state         <= S_IDLE;
            ret_state_after_mm <= S_IDLE;
            status_done   <= 1'b0;
            status_error  <= 1'b0;
            cycles_count  <= 32'd0;
            op_sel_latched <= 2'd0;

            keygen_start  <= 1'b0;
            enc_start     <= 1'b0;
            enc_in_we     <= 1'b0;
            enc_in_sel    <= 1'b0;
            enc_in_waddr  <= 11'd0;
            enc_in_wdata  <= 8'd0;
            dec_start     <= 1'b0;
            dec_in_we     <= 1'b0;
            dec_in_sel    <= 1'b0;
            dec_in_waddr  <= 12'd0;
            dec_in_wdata  <= 8'd0;

            byte_idx      <= 12'd0;
            bypass_wait_cnt <= 6'd0;

            mm_word_idx      <= 12'd0;
            mm_word_total    <= 12'd0;
            mm_base_addr     <= 32'd0;
            mm_buf_sel       <= BUF_PK;

            m_axi_awaddr   <= {C_M_AXI_ADDR_WIDTH{1'b0}};
            m_axi_awlen    <= 8'd0;
            m_axi_awsize   <= 3'd2;
            m_axi_awburst  <= 2'b01;
            m_axi_awvalid  <= 1'b0;
            m_axi_wdata    <= {C_M_AXI_DATA_WIDTH{1'b0}};
            m_axi_wstrb    <= {(C_M_AXI_DATA_WIDTH/8){1'b1}};
            m_axi_wlast    <= 1'b1;
            m_axi_wvalid   <= 1'b0;
            m_axi_bready   <= 1'b0;
            m_axi_araddr   <= {C_M_AXI_ADDR_WIDTH{1'b0}};
            m_axi_arlen    <= 8'd0;
            m_axi_arsize   <= 3'd2;
            m_axi_arburst  <= 2'b01;
            m_axi_arvalid  <= 1'b0;
            m_axi_rready   <= 1'b0;
        end else begin
            keygen_start <= 1'b0;
            enc_start    <= 1'b0;
            enc_in_we    <= 1'b0;
            dec_start    <= 1'b0;
            dec_in_we    <= 1'b0;

            if (state != S_IDLE) cycles_count <= cycles_count + 32'd1;

            case (state)
                S_IDLE: begin
                    if (cfg_start_pulse) begin
                        status_done  <= 1'b0;
                        status_error <= 1'b0;
                        cycles_count <= 32'd0;
                        op_sel_latched <= cfg_op_sel;
                        case (cfg_op_sel)
                            OP_KEYGEN: begin
                                if (BYPASS_CRYPTO != 0) begin
                                    mm_word_idx <= 12'd0;
                                    state <= S_BYPASS_FILL_PK;
                                end else begin
                                    state <= S_KEYGEN_START;
                                end
                            end
                            OP_ENCAPS: begin
                                if (BYPASS_CRYPTO != 0) begin
                                    mm_word_idx <= 12'd0;
                                    state <= S_BYPASS_FILL_CT;
                                end else begin
                                    state <= S_ENCAPS_READ_PK;
                                    mm_buf_sel <= BUF_PK;
                                    mm_base_addr <= cfg_pk_addr;
                                    mm_word_total <= 12'd296;
                                    mm_word_idx <= 12'd0;
                                    ret_state_after_mm <= S_ENCAPS_READ_M;
                                end
                            end
                            OP_DECAPS: begin
                                if (BYPASS_CRYPTO != 0) begin
                                    for (i = 0; i < 32; i = i + 1) ss_mem[i] <= i[7:0] + 8'h33;
                                    state <= S_WRITE_SS;
                                    mm_buf_sel <= BUF_SS;
                                    mm_base_addr <= cfg_ss_addr;
                                    mm_word_total <= 12'd8;
                                    mm_word_idx <= 12'd0;
                                    ret_state_after_mm <= S_DONE;
                                end else begin
                                    state <= S_DECAPS_READ_DK;
                                    mm_buf_sel <= BUF_DK;
                                    mm_base_addr <= cfg_sk_addr;
                                    mm_word_total <= 12'd600;
                                    mm_word_idx <= 12'd0;
                                    ret_state_after_mm <= S_DECAPS_READ_CT;
                                end
                            end
                            default: state <= S_ERR;
                        endcase
                    end
                end

                S_KEYGEN_START: begin
                    keygen_start <= 1'b1;
                    state <= S_KEYGEN_WAIT;
                end

                S_KEYGEN_WAIT: begin
                    if (keygen_done) begin
                        mm_buf_sel <= BUF_PK;
                        mm_base_addr <= cfg_pk_addr;
                        mm_word_total <= 12'd296;
                        mm_word_idx <= 12'd0;
                        ret_state_after_mm <= S_WRITE_SK;
                        state <= S_WRITE_PK;
                    end
                end

                S_ENCAPS_READ_PK: begin
                            state <= S_MM_RD_AR;
                end

                S_ENCAPS_READ_M: begin
                    mm_buf_sel <= BUF_M;
                    mm_base_addr <= cfg_m_addr;
                    mm_word_total <= 12'd8;
                    mm_word_idx <= 12'd0;
                    ret_state_after_mm <= S_ENCAPS_PRELOAD_EK_FETCH;
                            state <= S_MM_RD_AR;
                end

                // Issue BRAM word read for pk_mem[byte_idx/4]; rd_data observable
                // one cycle later in _SEND. enc_in_we stays 0 during FETCH.
                S_ENCAPS_PRELOAD_EK_FETCH: begin
                    state <= S_ENCAPS_PRELOAD_EK_SEND;
                end

                // Drain one byte from the fetched word. Fetch the next word when
                // the byte-lane wraps. After the last byte, advance to m preload.
                S_ENCAPS_PRELOAD_EK_SEND: begin
                    enc_in_we    <= 1'b1;
                    enc_in_sel   <= 1'b0;
                    enc_in_waddr <= byte_idx[10:0];
                    enc_in_wdata <= pk_byte_mux;
                    if (byte_idx == 12'd1183) begin
                        byte_idx <= 12'd0;
                        state    <= S_ENCAPS_PRELOAD_M;
                    end else if (byte_idx[1:0] == 2'b11) begin
                        byte_idx <= byte_idx + 12'd1;
                        state    <= S_ENCAPS_PRELOAD_EK_FETCH;
                    end else begin
                        byte_idx <= byte_idx + 12'd1;
                    end
                end

                S_ENCAPS_PRELOAD_M: begin
                    enc_in_we    <= 1'b1;
                    enc_in_sel   <= 1'b1;
                    enc_in_waddr <= byte_idx[10:0];
                    enc_in_wdata <= m_mem[byte_idx[4:0]];
                    if (byte_idx == 12'd31) begin
                        byte_idx <= 12'd0;
                        state <= S_ENCAPS_START;
                    end else begin
                        byte_idx <= byte_idx + 12'd1;
                    end
                end

                S_ENCAPS_START: begin
                    enc_start <= 1'b1;
                    state <= S_ENCAPS_WAIT;
                end

                S_ENCAPS_WAIT: begin
                    if (enc_done) begin
                        state <= S_CAPTURE_SS;
                    end
                end

                S_DECAPS_READ_DK: begin
                            state <= S_MM_RD_AR;
                end

                S_DECAPS_READ_CT: begin
                    mm_buf_sel <= BUF_CT;
                    mm_base_addr <= cfg_ct_addr;
                    mm_word_total <= 12'd272;
                    mm_word_idx <= 12'd0;
                    ret_state_after_mm <= S_DECAPS_PRELOAD_DK_FETCH;
                            state <= S_MM_RD_AR;
                end

                S_DECAPS_PRELOAD_DK_FETCH: begin
                    state <= S_DECAPS_PRELOAD_DK_SEND;
                end

                S_DECAPS_PRELOAD_DK_SEND: begin
                    dec_in_we    <= 1'b1;
                    dec_in_sel   <= 1'b0;
                    dec_in_waddr <= byte_idx;
                    dec_in_wdata <= dk_byte_mux;
                    if (byte_idx == 12'd2399) begin
                        byte_idx <= 12'd0;
                        state    <= S_DECAPS_PRELOAD_CT_FETCH;
                    end else if (byte_idx[1:0] == 2'b11) begin
                        byte_idx <= byte_idx + 12'd1;
                        state    <= S_DECAPS_PRELOAD_DK_FETCH;
                    end else begin
                        byte_idx <= byte_idx + 12'd1;
                    end
                end

                S_DECAPS_PRELOAD_CT_FETCH: begin
                    state <= S_DECAPS_PRELOAD_CT_SEND;
                end

                S_DECAPS_PRELOAD_CT_SEND: begin
                    dec_in_we    <= 1'b1;
                    dec_in_sel   <= 1'b1;
                    dec_in_waddr <= byte_idx;
                    dec_in_wdata <= ct_byte_mux;
                    if (byte_idx == 12'd1087) begin
                        byte_idx <= 12'd0;
                        state    <= S_DECAPS_START;
                    end else if (byte_idx[1:0] == 2'b11) begin
                        byte_idx <= byte_idx + 12'd1;
                        state    <= S_DECAPS_PRELOAD_CT_FETCH;
                    end else begin
                        byte_idx <= byte_idx + 12'd1;
                    end
                end

                S_DECAPS_START: begin
                    dec_start <= 1'b1;
                    state <= S_DECAPS_WAIT;
                end

                S_DECAPS_WAIT: begin
                    if (dec_done) begin
                        state <= S_CAPTURE_SS;
                    end
                end

                S_CAPTURE_SS: begin
                    if (op_sel_latched == OP_ENCAPS) begin
                        for (i = 0; i < 32; i = i + 1) ss_mem[i] <= enc_ss_out[i*8 +: 8];
                        mm_buf_sel <= BUF_CT;
                        mm_base_addr <= cfg_ct_addr;
                        mm_word_total <= 12'd272;
                        mm_word_idx <= 12'd0;
                        ret_state_after_mm <= S_WRITE_SS;
                        state <= S_WRITE_CT;
                    end else begin
                        for (i = 0; i < 32; i = i + 1) ss_mem[i] <= dec_ss_out[i*8 +: 8];
                        mm_buf_sel <= BUF_SS;
                        mm_base_addr <= cfg_ss_addr;
                        mm_word_total <= 12'd8;
                        mm_word_idx <= 12'd0;
                        ret_state_after_mm <= S_DONE;
                        state <= S_WRITE_SS;
                    end
                end

                S_WRITE_PK: begin
                    state <= S_MM_WR_AW_W;
                end

                S_WRITE_SK: begin
                    mm_buf_sel <= BUF_SK;
                    mm_base_addr <= cfg_sk_addr;
                    mm_word_total <= 12'd600;
                    mm_word_idx <= 12'd0;
                    ret_state_after_mm <= S_DONE;
                    state <= S_MM_WR_AW_W;
                end

                S_WRITE_CT: begin
                    state <= S_MM_WR_AW_W;
                end

                S_WRITE_SS: begin
                    mm_buf_sel <= BUF_SS;
                    mm_base_addr <= cfg_ss_addr;
                    mm_word_total <= 12'd8;
                    mm_word_idx <= 12'd0;
                    ret_state_after_mm <= S_DONE;
                    state <= S_MM_WR_AW_W;
                end

                S_MM_RD_AR: begin
                    m_axi_araddr  <= mm_base_addr + {{(C_M_AXI_ADDR_WIDTH-14){1'b0}}, mm_word_idx, 2'b00};
                    m_axi_arlen   <= 8'd0;
                    m_axi_arsize  <= 3'd2;
                    m_axi_arburst <= 2'b01;
                    m_axi_arvalid <= 1'b1;
                    m_axi_rready  <= 1'b0;
                    if (m_axi_arvalid && m_axi_arready) begin
                        m_axi_arvalid <= 1'b0;
                        m_axi_rready  <= 1'b1;
                        state <= S_MM_RD_R;
                    end
                end

                // Word write into the target BRAM is handled by the comb
                // write-port mux (axi_word_we => 4'b1111 strobes with
                // m_axi_rdata). BUF_M still goes to the reg array via its
                // dedicated always block below.
                S_MM_RD_R: begin
                    if (m_axi_rvalid && m_axi_rready) begin
                        m_axi_rready <= 1'b0;
                        if (m_axi_rresp != 2'b00) begin
                            state <= S_ERR;
                        end else begin
                            if (mm_word_idx == (mm_word_total - 12'd1)) begin
                                mm_word_idx <= 12'd0;
                                byte_idx <= 12'd0;
                                state <= ret_state_after_mm;
                            end else begin
                                mm_word_idx <= mm_word_idx + 12'd1;
                                state <= S_MM_RD_AR;
                            end
                        end
                    end
                end

                // AXI-MM write path:
                //   AW_W  : issue AW, wait for awready.
                //   FETCH : one cycle to issue BRAM read (rd_en comb) — rd_data
                //           settles at end of this cycle.
                //   W     : latch rd_data/m_word/ss_word into m_axi_wdata and
                //           assert wvalid; wait for wready → B.
                //   B     : wait for bvalid.
                S_MM_WR_AW_W: begin
                    if (!m_axi_awvalid) begin
                        m_axi_awaddr  <= mm_base_addr + {{(C_M_AXI_ADDR_WIDTH-14){1'b0}}, mm_word_idx, 2'b00};
                        m_axi_awlen   <= 8'd0;
                        m_axi_awsize  <= 3'd2;
                        m_axi_awburst <= 2'b01;
                        m_axi_awvalid <= 1'b1;
                    end
                    if (m_axi_awvalid && m_axi_awready) begin
                        m_axi_awvalid <= 1'b0;
                        state <= S_MM_WR_FETCH;
                    end
                end

                S_MM_WR_FETCH: begin
                    state <= S_MM_WR_W;
                end

                S_MM_WR_W: begin
                    if (!m_axi_wvalid) begin
                        m_axi_wdata  <= write_word_comb;
                        m_axi_wstrb  <= 4'hF;
                        m_axi_wlast  <= 1'b1;
                        m_axi_wvalid <= 1'b1;
                    end
                    if (m_axi_wvalid && m_axi_wready) begin
                        m_axi_wvalid <= 1'b0;
                        m_axi_bready <= 1'b1;
                        state <= S_MM_WR_B;
                    end
                end

                S_MM_WR_B: begin
                    if (m_axi_bvalid && m_axi_bready) begin
                        m_axi_bready <= 1'b0;
                        if (m_axi_bresp != 2'b00) begin
                            state <= S_ERR;
                        end else if (mm_word_idx == (mm_word_total - 12'd1)) begin
                            mm_word_idx <= 12'd0;
                            state <= ret_state_after_mm;
                        end else begin
                            mm_word_idx <= mm_word_idx + 12'd1;
                            state <= S_MM_WR_AW_W;
                        end
                    end
                end

                // BYPASS dummy fills: comb write-port mux drives wea/waddr/wdata
                // from bypass_fill_* state + mm_word_idx counter. Pattern matches
                // the original parallel-for fills (byte[i] = i ^ 0x5A / 0xA5 /
                // i + 0x11) so Gate A expectations on DDR content stay intact.
                S_BYPASS_FILL_PK: begin
                    if (mm_word_idx == 12'd295) begin
                        mm_word_idx <= 12'd0;
                        state <= S_BYPASS_FILL_SK;
                    end else begin
                        mm_word_idx <= mm_word_idx + 12'd1;
                    end
                end

                S_BYPASS_FILL_SK: begin
                    if (mm_word_idx == 12'd599) begin
                        mm_word_idx <= 12'd0;
                        bypass_wait_cnt <= 6'd16;
                        state <= S_BYPASS_WAIT;
                    end else begin
                        mm_word_idx <= mm_word_idx + 12'd1;
                    end
                end

                S_BYPASS_FILL_CT: begin
                    if (mm_word_idx == 12'd271) begin
                        for (i = 0; i < 32; i = i + 1) ss_mem[i] <= i[7:0] + 8'h77;
                        mm_buf_sel <= BUF_CT;
                        mm_base_addr <= cfg_ct_addr;
                        mm_word_total <= 12'd272;
                        mm_word_idx <= 12'd0;
                        ret_state_after_mm <= S_WRITE_SS;
                        state <= S_WRITE_CT;
                    end else begin
                        mm_word_idx <= mm_word_idx + 12'd1;
                    end
                end

                S_BYPASS_WAIT: begin
                    if (bypass_wait_cnt == 6'd0) begin
                        mm_buf_sel <= BUF_PK;
                        mm_base_addr <= cfg_pk_addr;
                        mm_word_total <= 12'd296;
                        mm_word_idx <= 12'd0;
                        ret_state_after_mm <= S_WRITE_SK;
                        state <= S_WRITE_PK;
                    end else begin
                        bypass_wait_cnt <= bypass_wait_cnt - 6'd1;
                    end
                end

                S_DONE: begin
                    status_done <= 1'b1;
                    state <= S_IDLE;
                end

                S_ERR: begin
                    status_error <= 1'b1;
                    status_done  <= 1'b1;
                    state <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

    // BUF_M: AXI-MM RDATA writes into the small reg array (parallel 4-byte write
    // in a single cycle since m_mem is distributed storage). Kept separate from
    // the BRAM mux for clarity.
    always @(posedge clk) begin
        if ((state == S_MM_RD_R) && m_axi_rvalid && m_axi_rready
            && (m_axi_rresp == 2'b00) && (mm_buf_sel == BUF_M)) begin
            m_mem[mm_word_idx*4]         <= m_axi_rdata[7:0];
            m_mem[mm_word_idx*4 + 12'd1] <= m_axi_rdata[15:8];
            m_mem[mm_word_idx*4 + 12'd2] <= m_axi_rdata[23:16];
            m_mem[mm_word_idx*4 + 12'd3] <= m_axi_rdata[31:24];
        end
    end

endmodule
