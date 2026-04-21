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
    localparam [7:0] S_ENCAPS_PRELOAD_EK    = 8'd5;
    localparam [7:0] S_ENCAPS_PRELOAD_M     = 8'd6;
    localparam [7:0] S_ENCAPS_START         = 8'd7;
    localparam [7:0] S_ENCAPS_WAIT          = 8'd8;
    localparam [7:0] S_DECAPS_READ_DK       = 8'd9;
    localparam [7:0] S_DECAPS_READ_CT       = 8'd10;
    localparam [7:0] S_DECAPS_PRELOAD_DK    = 8'd11;
    localparam [7:0] S_DECAPS_PRELOAD_CT    = 8'd12;
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
    reg        mm_write_not_read;

    reg [7:0] pk_mem [0:1183];
    reg [7:0] sk_mem [0:2399];
    reg [7:0] ct_mem [0:1087];
    reg [7:0] dk_mem [0:2399];
    reg [7:0] m_mem  [0:31];
    reg [7:0] ss_mem [0:31];

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

    reg [31:0] write_word_data;
    integer i;

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
            ml_kem_keygen u_keygen (
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
                .sk_dout(keygen_sk_dout)
            );

            ml_kem_encaps u_encaps (
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
                .ss_out(enc_ss_out)
            );

            ml_kem_decaps u_decaps (
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
                .ss_out(dec_ss_out)
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
        end
    endgenerate

    always @(*) begin
        case (mm_buf_sel)
            BUF_PK: write_word_data = {pk_mem[mm_word_idx*4 + 12'd3], pk_mem[mm_word_idx*4 + 12'd2], pk_mem[mm_word_idx*4 + 12'd1], pk_mem[mm_word_idx*4]};
            BUF_SK: write_word_data = {sk_mem[mm_word_idx*4 + 12'd3], sk_mem[mm_word_idx*4 + 12'd2], sk_mem[mm_word_idx*4 + 12'd1], sk_mem[mm_word_idx*4]};
            BUF_CT: write_word_data = {ct_mem[mm_word_idx*4 + 12'd3], ct_mem[mm_word_idx*4 + 12'd2], ct_mem[mm_word_idx*4 + 12'd1], ct_mem[mm_word_idx*4]};
            BUF_M:  write_word_data = {m_mem[mm_word_idx*4 + 12'd3], m_mem[mm_word_idx*4 + 12'd2], m_mem[mm_word_idx*4 + 12'd1], m_mem[mm_word_idx*4]};
            BUF_DK: write_word_data = {dk_mem[mm_word_idx*4 + 12'd3], dk_mem[mm_word_idx*4 + 12'd2], dk_mem[mm_word_idx*4 + 12'd1], dk_mem[mm_word_idx*4]};
            BUF_SS: write_word_data = {ss_mem[mm_word_idx*4 + 12'd3], ss_mem[mm_word_idx*4 + 12'd2], ss_mem[mm_word_idx*4 + 12'd1], ss_mem[mm_word_idx*4]};
            default: write_word_data = 32'd0;
        endcase
    end

    always @(posedge clk) begin
        if (keygen_pk_we && (keygen_pk_addr < 11'd1184)) pk_mem[keygen_pk_addr] <= keygen_pk_dout;
        if (keygen_sk_we && (keygen_sk_addr < 12'd2400)) sk_mem[keygen_sk_addr] <= keygen_sk_dout;
        if (enc_ct_we && (enc_ct_addr < 11'd1088)) ct_mem[enc_ct_addr] <= enc_ct_dout;
    end

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
            mm_write_not_read <= 1'b0;

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
                                    for (i = 0; i < 1184; i = i + 1) pk_mem[i] <= i[7:0] ^ 8'h5A;
                                    for (i = 0; i < 2400; i = i + 1) sk_mem[i] <= i[7:0] ^ 8'hA5;
                                    bypass_wait_cnt <= 6'd16;
                                    state <= S_BYPASS_WAIT;
                                end else begin
                                    state <= S_KEYGEN_START;
                                end
                            end
                            OP_ENCAPS: begin
                                if (BYPASS_CRYPTO != 0) begin
                                    for (i = 0; i < 1088; i = i + 1) ct_mem[i] <= i[7:0] + 8'h11;
                                    for (i = 0; i < 32; i = i + 1) ss_mem[i] <= i[7:0] + 8'h77;
                                    state <= S_WRITE_CT;
                                    mm_buf_sel <= BUF_CT;
                                    mm_base_addr <= cfg_ct_addr;
                                    mm_word_total <= 12'd272;
                                    mm_word_idx <= 12'd0;
                                    ret_state_after_mm <= S_WRITE_SS;
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
                    mm_write_not_read <= 1'b0;
                    state <= S_MM_RD_AR;
                end

                S_ENCAPS_READ_M: begin
                    mm_buf_sel <= BUF_M;
                    mm_base_addr <= cfg_m_addr;
                    mm_word_total <= 12'd8;
                    mm_word_idx <= 12'd0;
                    ret_state_after_mm <= S_ENCAPS_PRELOAD_EK;
                    mm_write_not_read <= 1'b0;
                    state <= S_MM_RD_AR;
                end

                S_ENCAPS_PRELOAD_EK: begin
                    enc_in_we    <= 1'b1;
                    enc_in_sel   <= 1'b0;
                    enc_in_waddr <= byte_idx[10:0];
                    enc_in_wdata <= pk_mem[byte_idx];
                    if (byte_idx == 12'd1183) begin
                        byte_idx <= 12'd0;
                        state <= S_ENCAPS_PRELOAD_M;
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
                    mm_write_not_read <= 1'b0;
                    state <= S_MM_RD_AR;
                end

                S_DECAPS_READ_CT: begin
                    mm_buf_sel <= BUF_CT;
                    mm_base_addr <= cfg_ct_addr;
                    mm_word_total <= 12'd272;
                    mm_word_idx <= 12'd0;
                    ret_state_after_mm <= S_DECAPS_PRELOAD_DK;
                    mm_write_not_read <= 1'b0;
                    state <= S_MM_RD_AR;
                end

                S_DECAPS_PRELOAD_DK: begin
                    dec_in_we    <= 1'b1;
                    dec_in_sel   <= 1'b0;
                    dec_in_waddr <= byte_idx;
                    dec_in_wdata <= dk_mem[byte_idx];
                    if (byte_idx == 12'd2399) begin
                        byte_idx <= 12'd0;
                        state <= S_DECAPS_PRELOAD_CT;
                    end else begin
                        byte_idx <= byte_idx + 12'd1;
                    end
                end

                S_DECAPS_PRELOAD_CT: begin
                    dec_in_we    <= 1'b1;
                    dec_in_sel   <= 1'b1;
                    dec_in_waddr <= byte_idx;
                    dec_in_wdata <= ct_mem[byte_idx[10:0]];
                    if (byte_idx == 12'd1087) begin
                        byte_idx <= 12'd0;
                        state <= S_DECAPS_START;
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
                    mm_write_not_read <= 1'b1;
                    state <= S_MM_WR_AW_W;
                end

                S_WRITE_SK: begin
                    mm_buf_sel <= BUF_SK;
                    mm_base_addr <= cfg_sk_addr;
                    mm_word_total <= 12'd600;
                    mm_word_idx <= 12'd0;
                    ret_state_after_mm <= S_DONE;
                    mm_write_not_read <= 1'b1;
                    state <= S_MM_WR_AW_W;
                end

                S_WRITE_CT: begin
                    mm_write_not_read <= 1'b1;
                    state <= S_MM_WR_AW_W;
                end

                S_WRITE_SS: begin
                    mm_buf_sel <= BUF_SS;
                    mm_base_addr <= cfg_ss_addr;
                    mm_word_total <= 12'd8;
                    mm_word_idx <= 12'd0;
                    ret_state_after_mm <= S_DONE;
                    mm_write_not_read <= 1'b1;
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

                S_MM_RD_R: begin
                    if (m_axi_rvalid && m_axi_rready) begin
                        m_axi_rready <= 1'b0;
                        if (m_axi_rresp != 2'b00) begin
                            state <= S_ERR;
                        end else begin
                            case (mm_buf_sel)
                                BUF_PK: begin
                                    pk_mem[mm_word_idx*4]         <= m_axi_rdata[7:0];
                                    pk_mem[mm_word_idx*4 + 12'd1] <= m_axi_rdata[15:8];
                                    pk_mem[mm_word_idx*4 + 12'd2] <= m_axi_rdata[23:16];
                                    pk_mem[mm_word_idx*4 + 12'd3] <= m_axi_rdata[31:24];
                                end
                                BUF_SK: begin
                                    sk_mem[mm_word_idx*4]         <= m_axi_rdata[7:0];
                                    sk_mem[mm_word_idx*4 + 12'd1] <= m_axi_rdata[15:8];
                                    sk_mem[mm_word_idx*4 + 12'd2] <= m_axi_rdata[23:16];
                                    sk_mem[mm_word_idx*4 + 12'd3] <= m_axi_rdata[31:24];
                                end
                                BUF_CT: begin
                                    ct_mem[mm_word_idx*4]         <= m_axi_rdata[7:0];
                                    ct_mem[mm_word_idx*4 + 12'd1] <= m_axi_rdata[15:8];
                                    ct_mem[mm_word_idx*4 + 12'd2] <= m_axi_rdata[23:16];
                                    ct_mem[mm_word_idx*4 + 12'd3] <= m_axi_rdata[31:24];
                                end
                                BUF_M: begin
                                    m_mem[mm_word_idx*4]         <= m_axi_rdata[7:0];
                                    m_mem[mm_word_idx*4 + 12'd1] <= m_axi_rdata[15:8];
                                    m_mem[mm_word_idx*4 + 12'd2] <= m_axi_rdata[23:16];
                                    m_mem[mm_word_idx*4 + 12'd3] <= m_axi_rdata[31:24];
                                end
                                BUF_DK: begin
                                    dk_mem[mm_word_idx*4]         <= m_axi_rdata[7:0];
                                    dk_mem[mm_word_idx*4 + 12'd1] <= m_axi_rdata[15:8];
                                    dk_mem[mm_word_idx*4 + 12'd2] <= m_axi_rdata[23:16];
                                    dk_mem[mm_word_idx*4 + 12'd3] <= m_axi_rdata[31:24];
                                end
                                default: begin
                                end
                            endcase

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
                        state <= S_MM_WR_W;
                    end
                end

                S_MM_WR_W: begin
                    if (!m_axi_wvalid) begin
                        m_axi_wdata  <= write_word_data;
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

endmodule
