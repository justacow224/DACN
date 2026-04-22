`timescale 1ns / 1ps

module tb_ml_kem_top;

    localparam int C_S_AXI_ADDR_WIDTH = 8;
    localparam int C_S_AXI_DATA_WIDTH = 32;
    localparam int C_M_AXI_ADDR_WIDTH = 32;
    localparam int C_M_AXI_DATA_WIDTH = 32;
    localparam int TB_BYPASS_CRYPTO   = 0;

    localparam int PK_BASE = 32'h0000_1000;
    localparam int SK_BASE = 32'h0000_2000;
    localparam int CT_BASE = 32'h0000_3000;
    localparam int SS_BASE = 32'h0000_4000;
    localparam int M_BASE  = 32'h0000_5000;

    reg clk;
    reg rst_n;

    reg  [C_S_AXI_ADDR_WIDTH-1:0] s_axi_awaddr;
    reg                           s_axi_awvalid;
    wire                          s_axi_awready;
    reg  [C_S_AXI_DATA_WIDTH-1:0] s_axi_wdata;
    reg  [(C_S_AXI_DATA_WIDTH/8)-1:0] s_axi_wstrb;
    reg                           s_axi_wvalid;
    wire                          s_axi_wready;
    wire [1:0]                    s_axi_bresp;
    wire                          s_axi_bvalid;
    reg                           s_axi_bready;
    reg  [C_S_AXI_ADDR_WIDTH-1:0] s_axi_araddr;
    reg                           s_axi_arvalid;
    wire                          s_axi_arready;
    wire [C_S_AXI_DATA_WIDTH-1:0] s_axi_rdata;
    wire [1:0]                    s_axi_rresp;
    wire                          s_axi_rvalid;
    reg                           s_axi_rready;

    wire [C_M_AXI_ADDR_WIDTH-1:0] m_axi_awaddr;
    wire [7:0]                    m_axi_awlen;
    wire [2:0]                    m_axi_awsize;
    wire [1:0]                    m_axi_awburst;
    wire                          m_axi_awvalid;
    reg                           m_axi_awready;
    wire [C_M_AXI_DATA_WIDTH-1:0] m_axi_wdata;
    wire [(C_M_AXI_DATA_WIDTH/8)-1:0] m_axi_wstrb;
    wire                          m_axi_wlast;
    wire                          m_axi_wvalid;
    reg                           m_axi_wready;
    reg  [1:0]                    m_axi_bresp;
    reg                           m_axi_bvalid;
    wire                          m_axi_bready;
    wire [C_M_AXI_ADDR_WIDTH-1:0] m_axi_araddr;
    wire [7:0]                    m_axi_arlen;
    wire [2:0]                    m_axi_arsize;
    wire [1:0]                    m_axi_arburst;
    wire                          m_axi_arvalid;
    reg                           m_axi_arready;
    reg  [C_M_AXI_DATA_WIDTH-1:0] m_axi_rdata;
    reg  [1:0]                    m_axi_rresp;
    reg                           m_axi_rlast;
    reg                           m_axi_rvalid;
    wire                          m_axi_rready;

    reg [7:0] ddr_mem [0:65535];
    reg [31:0] awaddr_lat;
    reg [31:0] wdata_lat;
    reg [3:0]  wstrb_lat;
    reg aw_seen;
    reg w_seen;
    reg mm_stall_enable;
    reg [7:0] mm_stall_ctr;
    reg inject_bresp_err;
    reg [11:0] inject_bresp_err_beat;
    reg inject_rresp_err;
    reg [11:0] inject_rresp_err_beat;
    reg [31:0] rd;
    reg [7:0] ss_enc [0:31];
    reg [7:0] ss_dec [0:31];
    integer i;
    integer dbg_sk_vs_ddr;
    integer dbg_dk_vs_ddr;
    integer dbg_ct_vs_ddr;
    integer dbg_dk_vs_sk;
    integer dbg_pk_vs_sk_pk;
    integer dbg_h_keygen_vs_encaps;
    integer dbg_h_keygen_vs_sk;

    ml_kem_top #(
        .C_S_AXI_ADDR_WIDTH(C_S_AXI_ADDR_WIDTH),
        .C_S_AXI_DATA_WIDTH(C_S_AXI_DATA_WIDTH),
        .C_M_AXI_ADDR_WIDTH(C_M_AXI_ADDR_WIDTH),
        .C_M_AXI_DATA_WIDTH(C_M_AXI_DATA_WIDTH),
        .BYPASS_CRYPTO(TB_BYPASS_CRYPTO)
    ) dut (
        .clk(clk),
        .rst_n(rst_n),
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
        .m_axi_awaddr(m_axi_awaddr),
        .m_axi_awlen(m_axi_awlen),
        .m_axi_awsize(m_axi_awsize),
        .m_axi_awburst(m_axi_awburst),
        .m_axi_awvalid(m_axi_awvalid),
        .m_axi_awready(m_axi_awready),
        .m_axi_wdata(m_axi_wdata),
        .m_axi_wstrb(m_axi_wstrb),
        .m_axi_wlast(m_axi_wlast),
        .m_axi_wvalid(m_axi_wvalid),
        .m_axi_wready(m_axi_wready),
        .m_axi_bresp(m_axi_bresp),
        .m_axi_bvalid(m_axi_bvalid),
        .m_axi_bready(m_axi_bready),
        .m_axi_araddr(m_axi_araddr),
        .m_axi_arlen(m_axi_arlen),
        .m_axi_arsize(m_axi_arsize),
        .m_axi_arburst(m_axi_arburst),
        .m_axi_arvalid(m_axi_arvalid),
        .m_axi_arready(m_axi_arready),
        .m_axi_rdata(m_axi_rdata),
        .m_axi_rresp(m_axi_rresp),
        .m_axi_rlast(m_axi_rlast),
        .m_axi_rvalid(m_axi_rvalid),
        .m_axi_rready(m_axi_rready)
    );

    always #5 clk = ~clk;

    task automatic axi_write32(input [7:0] addr, input [31:0] data);
        integer to;
        reg aw_done;
        reg w_done;
    begin
        @(posedge clk);
        s_axi_awaddr  <= addr;
        s_axi_awvalid <= 1'b1;
        s_axi_wdata   <= data;
        s_axi_wstrb   <= 4'hF;
        s_axi_wvalid  <= 1'b1;
        s_axi_bready  <= 1'b1;
        aw_done = 1'b0;
        w_done  = 1'b0;
        to = 0;
        while (!(aw_done && w_done)) begin
            @(posedge clk);
            if (!aw_done && s_axi_awvalid && s_axi_awready) begin
                aw_done = 1'b1;
                s_axi_awvalid <= 1'b0;
            end
            if (!w_done && s_axi_wvalid && s_axi_wready) begin
                w_done = 1'b1;
                s_axi_wvalid <= 1'b0;
            end
            to = to + 1;
            if (to > 2000) begin
                $fatal(1, "AXI-Lite write handshake timeout at addr 0x%02h", addr);
            end
        end

        to = 0;
        while (!s_axi_bvalid) begin
            @(posedge clk);
            to = to + 1;
            if (to > 2000) begin
                $fatal(1, "AXI-Lite write response timeout at addr 0x%02h", addr);
            end
        end
        @(posedge clk);
        s_axi_bready  <= 1'b0;
    end
    endtask

    task automatic axi_write32_strb(input [7:0] addr, input [31:0] data, input [3:0] strb);
        integer to;
        reg aw_done;
        reg w_done;
    begin
        @(posedge clk);
        s_axi_awaddr  <= addr;
        s_axi_awvalid <= 1'b1;
        s_axi_wdata   <= data;
        s_axi_wstrb   <= strb;
        s_axi_wvalid  <= 1'b1;
        s_axi_bready  <= 1'b1;
        aw_done = 1'b0;
        w_done  = 1'b0;
        to = 0;
        while (!(aw_done && w_done)) begin
            @(posedge clk);
            if (!aw_done && s_axi_awvalid && s_axi_awready) begin
                aw_done = 1'b1;
                s_axi_awvalid <= 1'b0;
            end
            if (!w_done && s_axi_wvalid && s_axi_wready) begin
                w_done = 1'b1;
                s_axi_wvalid <= 1'b0;
            end
            to = to + 1;
            if (to > 2000) begin
                $fatal(1, "AXI-Lite write(strb) handshake timeout at addr 0x%02h", addr);
            end
        end

        to = 0;
        while (!s_axi_bvalid) begin
            @(posedge clk);
            to = to + 1;
            if (to > 2000) begin
                $fatal(1, "AXI-Lite write(strb) response timeout at addr 0x%02h", addr);
            end
        end
        @(posedge clk);
        s_axi_bready  <= 1'b0;
    end
    endtask

    task automatic axi_write32_aw_first(input [7:0] addr, input [31:0] data);
        integer to;
    begin
        @(posedge clk);
        s_axi_awaddr  <= addr;
        s_axi_awvalid <= 1'b1;
        s_axi_wdata   <= data;
        s_axi_wstrb   <= 4'hF;
        s_axi_wvalid  <= 1'b0;
        s_axi_bready  <= 1'b1;

        to = 0;
        while (!(s_axi_awvalid && s_axi_awready)) begin
            @(posedge clk);
            to = to + 1;
            if (to > 2000) begin
                $fatal(1, "AXI-Lite AW-first AW timeout at addr 0x%02h", addr);
            end
        end
        @(posedge clk);
        s_axi_awvalid <= 1'b0;
        s_axi_wvalid  <= 1'b1;

        to = 0;
        while (!(s_axi_wvalid && s_axi_wready)) begin
            @(posedge clk);
            to = to + 1;
            if (to > 2000) begin
                $fatal(1, "AXI-Lite AW-first W timeout at addr 0x%02h", addr);
            end
        end
        @(posedge clk);
        s_axi_wvalid <= 1'b0;

        to = 0;
        while (!s_axi_bvalid) begin
            @(posedge clk);
            to = to + 1;
            if (to > 2000) begin
                $fatal(1, "AXI-Lite AW-first B timeout at addr 0x%02h", addr);
            end
        end
        @(posedge clk);
        s_axi_bready  <= 1'b0;
    end
    endtask

    task automatic axi_write32_w_first(input [7:0] addr, input [31:0] data);
        integer to;
    begin
        @(posedge clk);
        s_axi_awaddr  <= addr;
        s_axi_awvalid <= 1'b0;
        s_axi_wdata   <= data;
        s_axi_wstrb   <= 4'hF;
        s_axi_wvalid  <= 1'b1;
        s_axi_bready  <= 1'b1;

        to = 0;
        while (!(s_axi_wvalid && s_axi_wready)) begin
            @(posedge clk);
            to = to + 1;
            if (to > 2000) begin
                $fatal(1, "AXI-Lite W-first W timeout at addr 0x%02h", addr);
            end
        end
        @(posedge clk);
        s_axi_wvalid  <= 1'b0;
        s_axi_awvalid <= 1'b1;

        to = 0;
        while (!(s_axi_awvalid && s_axi_awready)) begin
            @(posedge clk);
            to = to + 1;
            if (to > 2000) begin
                $fatal(1, "AXI-Lite W-first AW timeout at addr 0x%02h", addr);
            end
        end
        @(posedge clk);
        s_axi_awvalid <= 1'b0;

        to = 0;
        while (!s_axi_bvalid) begin
            @(posedge clk);
            to = to + 1;
            if (to > 2000) begin
                $fatal(1, "AXI-Lite W-first B timeout at addr 0x%02h", addr);
            end
        end
        @(posedge clk);
        s_axi_bready  <= 1'b0;
    end
    endtask

    task automatic axi_read32(input [7:0] addr, output [31:0] data);
        integer to;
        reg ar_done;
    begin
        @(posedge clk);
        s_axi_araddr  <= addr;
        s_axi_arvalid <= 1'b1;
        s_axi_rready  <= 1'b1;
        ar_done = 1'b0;
        to = 0;
        while (!ar_done) begin
            @(posedge clk);
            if (s_axi_arvalid && s_axi_arready) begin
                ar_done = 1'b1;
                s_axi_arvalid <= 1'b0;
            end
            to = to + 1;
            if (to > 2000) begin
                $fatal(1, "AXI-Lite read address handshake timeout at addr 0x%02h", addr);
            end
        end

        to = 0;
        while (!s_axi_rvalid) begin
            @(posedge clk);
            to = to + 1;
            if (to > 2000) begin
                $fatal(1, "AXI-Lite read data timeout at addr 0x%02h", addr);
            end
        end
        data = s_axi_rdata;
        @(posedge clk);
        s_axi_rready <= 1'b0;
    end
    endtask

    task automatic wait_done_limit(input integer max_poll);
        reg [31:0] st;
        integer to;
    begin
        // Phase A: ensure new command has been accepted (done must clear).
        st = 32'hFFFF_FFFF;
        to = 0;
        while (st[0] == 1'b1) begin
            axi_read32(8'h04, st);
            to = to + 1;
            if (to > max_poll) begin
                $fatal(1, "wait_done(clear) timeout. STATUS=0x%08h state=%0d mm_word_idx=%0d mm_word_total=%0d",
                       st, dut.state, dut.mm_word_idx, dut.mm_word_total);
            end
        end

        // Phase B: wait for operation complete (done rises).
        to = 0;
        while (st[0] == 1'b0) begin
            axi_read32(8'h04, st);
            to = to + 1;
            if (to > max_poll) begin
                $fatal(1, "wait_done(set) timeout. STATUS=0x%08h state=%0d mm_word_idx=%0d mm_word_total=%0d",
                       st, dut.state, dut.mm_word_idx, dut.mm_word_total);
            end
        end
    end
    endtask

    task automatic wait_done;
    begin
        wait_done_limit(20000);
    end
    endtask

    task automatic expect_status(input bit exp_done, input bit exp_idle, input bit exp_error);
        reg [31:0] st;
    begin
        axi_read32(8'h04, st);
        if ((st[0] !== exp_done) || (st[1] !== exp_idle) || (st[2] !== exp_error)) begin
            $fatal(1, "STATUS mismatch. got=0x%08h exp(done,idle,error)=%0d%0d%0d",
                   st, exp_done, exp_idle, exp_error);
        end
    end
    endtask

    task automatic expect_ctrl(input [1:0] exp_op_sel);
        reg [31:0] ctrl;
    begin
        axi_read32(8'h00, ctrl);
        if ((ctrl[0] !== 1'b0) || (ctrl[2:1] !== exp_op_sel) || (ctrl[31:3] !== 29'd0)) begin
            $fatal(1, "CTRL mismatch. got=0x%08h exp_op_sel=%0d", ctrl, exp_op_sel);
        end
    end
    endtask

    always @(posedge clk) begin
        if (!rst_n) begin
            m_axi_awready <= 1'b1;
            m_axi_wready  <= 1'b1;
            m_axi_bresp   <= 2'b00;
            m_axi_bvalid  <= 1'b0;
            m_axi_arready <= 1'b1;
            m_axi_rdata   <= 32'd0;
            m_axi_rresp   <= 2'b00;
            m_axi_rlast   <= 1'b1;
            m_axi_rvalid  <= 1'b0;
            awaddr_lat    <= 32'd0;
            wdata_lat     <= 32'd0;
            wstrb_lat     <= 4'd0;
            aw_seen       <= 1'b0;
            w_seen        <= 1'b0;
            mm_stall_ctr  <= 8'd0;
            mm_stall_enable <= 1'b0;
            inject_bresp_err <= 1'b0;
            inject_bresp_err_beat <= 12'd0;
            inject_rresp_err <= 1'b0;
            inject_rresp_err_beat <= 12'd0;
        end else begin
            if (mm_stall_enable) begin
                mm_stall_ctr <= mm_stall_ctr + 8'd1;
                m_axi_awready <= (mm_stall_ctr[1:0] != 2'b00);
                m_axi_wready  <= (mm_stall_ctr[1:0] != 2'b01);
                m_axi_arready <= (mm_stall_ctr[1:0] != 2'b10);
            end else begin
                mm_stall_ctr <= 8'd0;
                m_axi_awready <= 1'b1;
                m_axi_wready  <= 1'b1;
                m_axi_arready <= 1'b1;
            end

            if (m_axi_awvalid && m_axi_awready) begin
                awaddr_lat <= m_axi_awaddr;
                aw_seen    <= 1'b1;
            end
            if (m_axi_wvalid && m_axi_wready) begin
                wdata_lat <= m_axi_wdata;
                wstrb_lat <= m_axi_wstrb;
                w_seen <= 1'b1;
            end
            if (aw_seen && w_seen && !m_axi_bvalid) begin
                if (wstrb_lat[0]) ddr_mem[awaddr_lat + 32'd0] <= wdata_lat[7:0];
                if (wstrb_lat[1]) ddr_mem[awaddr_lat + 32'd1] <= wdata_lat[15:8];
                if (wstrb_lat[2]) ddr_mem[awaddr_lat + 32'd2] <= wdata_lat[23:16];
                if (wstrb_lat[3]) ddr_mem[awaddr_lat + 32'd3] <= wdata_lat[31:24];
                if (inject_bresp_err) begin
                    if (inject_bresp_err_beat == 12'd0) begin
                        m_axi_bresp <= 2'b10;
                        inject_bresp_err <= 1'b0;
                    end else begin
                        inject_bresp_err_beat <= inject_bresp_err_beat - 12'd1;
                        m_axi_bresp <= 2'b00;
                    end
                end else begin
                    m_axi_bresp <= 2'b00;
                end
                m_axi_bvalid <= 1'b1;
                aw_seen <= 1'b0;
                w_seen <= 1'b0;
            end
            if (m_axi_bvalid && m_axi_bready) begin
                m_axi_bvalid <= 1'b0;
            end

            if (m_axi_arvalid && m_axi_arready && !m_axi_rvalid) begin
                m_axi_rdata <= {
                    ddr_mem[m_axi_araddr + 32'd3],
                    ddr_mem[m_axi_araddr + 32'd2],
                    ddr_mem[m_axi_araddr + 32'd1],
                    ddr_mem[m_axi_araddr + 32'd0]
                };
                if (inject_rresp_err) begin
                    if (inject_rresp_err_beat == 12'd0) begin
                        m_axi_rresp <= 2'b10;
                        inject_rresp_err <= 1'b0;
                    end else begin
                        inject_rresp_err_beat <= inject_rresp_err_beat - 12'd1;
                        m_axi_rresp <= 2'b00;
                    end
                end else begin
                    m_axi_rresp <= 2'b00;
                end
                m_axi_rvalid <= 1'b1;
            end
            if (m_axi_rvalid && m_axi_rready) begin
                m_axi_rvalid <= 1'b0;
                m_axi_rresp <= 2'b00;
            end
        end
    end

    // ----------------------------------------------------------------
    // Probe aliases for Gate B hierarchical taps into g_crypto_real.*
    // When TB_BYPASS_CRYPTO=1, g_crypto_real isn't elaborated, so the
    // real-path assigns live inside an inactive generate branch and
    // the elaborator only sees the zeroed fallback. Gate B code path
    // is runtime-guarded by dut.BYPASS_CRYPTO, so zeros never get read
    // in Gate A mode.
    // ----------------------------------------------------------------
    wire [7:0]  probe_h_pk_reg [0:31];
    wire [7:0]  probe_encaps_h_buf [0:31];
    wire [7:0]  probe_dec_k_prime [0:31];
    wire [7:0]  probe_dec_k_reject [0:31];
    wire        probe_dec_match_reg;
    wire [31:0] probe_dec_xor_acc;
    wire [31:0] probe_dec_cmp_seen;
    wire [31:0] probe_dec_cmp_idx;
    wire [7:0]  probe_dec_ct_byte;
    wire [7:0]  probe_dec_ct_prime_byte;
    wire [31:0] probe_dec_enc_ct_count;
    wire [7:0]  probe_dec_m_out;

    generate
        if (TB_BYPASS_CRYPTO == 0) begin : g_probe
            genvar gi;
            for (gi = 0; gi < 32; gi = gi + 1) begin : g_arr
                assign probe_h_pk_reg[gi]     = probe_h_pk_reg[gi];
                assign probe_encaps_h_buf[gi] = probe_encaps_h_buf[gi];
                assign probe_dec_k_prime[gi]  = probe_dec_k_prime[gi];
                assign probe_dec_k_reject[gi] = probe_dec_k_reject[gi];
            end
            assign probe_dec_match_reg      = probe_dec_match_reg;
            assign probe_dec_xor_acc        = probe_dec_xor_acc;
            assign probe_dec_cmp_seen       = probe_dec_cmp_seen;
            assign probe_dec_cmp_idx        = probe_dec_cmp_idx;
            assign probe_dec_ct_byte        = probe_dec_ct_byte;
            assign probe_dec_ct_prime_byte  = probe_dec_ct_prime_byte;
            assign probe_dec_enc_ct_count   = probe_dec_enc_ct_count;
            assign probe_dec_m_out          = probe_dec_m_out;
        end else begin : g_probe
            genvar gi2;
            for (gi2 = 0; gi2 < 32; gi2 = gi2 + 1) begin : g_arr
                assign probe_h_pk_reg[gi2]     = 8'd0;
                assign probe_encaps_h_buf[gi2] = 8'd0;
                assign probe_dec_k_prime[gi2]  = 8'd0;
                assign probe_dec_k_reject[gi2] = 8'd0;
            end
            assign probe_dec_match_reg      = 1'b0;
            assign probe_dec_xor_acc        = 32'd0;
            assign probe_dec_cmp_seen       = 32'd0;
            assign probe_dec_cmp_idx        = 32'd0;
            assign probe_dec_ct_byte        = 8'd0;
            assign probe_dec_ct_prime_byte  = 8'd0;
            assign probe_dec_enc_ct_count   = 32'd0;
            assign probe_dec_m_out          = 8'd0;
        end
    endgenerate

    initial begin
        clk = 1'b0;
        rst_n = 1'b0;
        s_axi_awaddr = '0;
        s_axi_awvalid = 1'b0;
        s_axi_wdata = '0;
        s_axi_wstrb = '0;
        s_axi_wvalid = 1'b0;
        s_axi_bready = 1'b0;
        s_axi_araddr = '0;
        s_axi_arvalid = 1'b0;
        s_axi_rready = 1'b0;

        for (i = 0; i < 65536; i = i + 1) ddr_mem[i] = 8'd0;

        repeat (10) @(posedge clk);
        rst_n = 1'b1;
        repeat (5) @(posedge clk);

        if (dut.BYPASS_CRYPTO != 0) begin
            // Gate A - Infra checks (AXI-Lite register semantics)
            axi_read32(8'h00, rd);
            if (rd !== 32'h0000_0000) $fatal(1, "CTRL reset mismatch: 0x%08h", rd);
            expect_status(1'b0, 1'b1, 1'b0);
            axi_read32(8'h08, rd);
            if (rd !== 32'h0000_0000) $fatal(1, "CYCLES reset mismatch: 0x%08h", rd);

            // Read-only registers must ignore write attempts.
            axi_write32(8'h04, 32'hFFFF_FFFF); // STATUS (RO)
            axi_write32(8'h08, 32'hDEAD_BEEF); // CYCLES (RO)
            expect_status(1'b0, 1'b1, 1'b0);
            axi_read32(8'h08, rd);
            if (rd !== 32'h0000_0000) $fatal(1, "CYCLES changed by RO write: 0x%08h", rd);

            // WSTRB behavior on RW address register.
            axi_write32(8'h50, 32'h0000_0000);
            axi_write32_strb(8'h50, 32'hA1B2_C3D4, 4'b0011);
            axi_read32(8'h50, rd);
            if (rd !== 32'h0000_C3D4) $fatal(1, "WSTRB low-byte write mismatch: 0x%08h", rd);
            axi_write32_strb(8'h50, 32'hA1B2_0000, 4'b1100);
            axi_read32(8'h50, rd);
            if (rd !== 32'hA1B2_C3D4) $fatal(1, "WSTRB high-byte write mismatch: 0x%08h", rd);

            // AW/W arrival ordering variants.
            axi_write32_aw_first(8'h60, M_BASE + 32'h40);
            axi_read32(8'h60, rd);
            if (rd !== (M_BASE + 32'h40)) $fatal(1, "AW-first write mismatch: 0x%08h", rd);
            axi_write32_w_first(8'h60, M_BASE);
            axi_read32(8'h60, rd);
            if (rd !== M_BASE) $fatal(1, "W-first write mismatch: 0x%08h", rd);

            // Restore test addresses.
            axi_write32(8'h50, PK_BASE);
            axi_write32(8'h54, SK_BASE);
            axi_write32(8'h58, CT_BASE);
            axi_write32(8'h5C, SS_BASE);
            axi_write32(8'h60, M_BASE);

            // KeyGen nominal.
            axi_write32_aw_first(8'h00, 32'h0000_0001);
            expect_ctrl(2'd0);
            wait_done();
            expect_status(1'b1, 1'b1, 1'b0);
            axi_read32(8'h08, rd);
            if (rd == 32'd0) $fatal(1, "CYCLES should be non-zero after KeyGen");

            for (i = 0; i < 1184; i = i + 1) begin
                if (ddr_mem[PK_BASE + i] !== ((i[7:0]) ^ 8'h5A)) begin
                    $fatal(1, "KeyGen PK mismatch at byte %0d", i);
                end
            end
            for (i = 0; i < 2400; i = i + 1) begin
                if (ddr_mem[SK_BASE + i] !== ((i[7:0]) ^ 8'hA5)) begin
                    $fatal(1, "KeyGen SK mismatch at byte %0d", i);
                end
            end

            // Encaps nominal.
            axi_write32_w_first(8'h00, 32'h0000_0003);
            expect_ctrl(2'd1);
            wait_done();
            expect_status(1'b1, 1'b1, 1'b0);
            for (i = 0; i < 1088; i = i + 1) begin
                if (ddr_mem[CT_BASE + i] !== (i[7:0] + 8'h11)) begin
                    $fatal(1, "Encaps CT mismatch at byte %0d", i);
                end
            end
            for (i = 0; i < 32; i = i + 1) begin
                if (ddr_mem[SS_BASE + i] !== (i[7:0] + 8'h77)) begin
                    $fatal(1, "Encaps SS mismatch at byte %0d", i);
                end
            end

            // Decaps with AXI-MM backpressure.
            mm_stall_enable = 1'b1;
            axi_write32(8'h00, 32'h0000_0005);
            expect_ctrl(2'd2);
            wait_done();
            mm_stall_enable = 1'b0;
            expect_status(1'b1, 1'b1, 1'b0);
            for (i = 0; i < 32; i = i + 1) begin
                if (ddr_mem[SS_BASE + i] !== (i[7:0] + 8'h33)) begin
                    $fatal(1, "Decaps SS mismatch at byte %0d", i);
                end
            end

            // BRESP error injection on write path -> expect status_error.
            inject_bresp_err = 1'b1;
            inject_bresp_err_beat = 12'd0; // first write response beat (deterministic)
            axi_write32(8'h00, 32'h0000_0005);
            wait_done();
            expect_status(1'b1, 1'b1, 1'b1);

            // Recover from error by starting a clean op.
            axi_write32(8'h00, 32'h0000_0001);
            wait_done();
            expect_status(1'b1, 1'b1, 1'b0);

            $display("INFO: Skip RRESP injection test in BYPASS_CRYPTO=1 (no AXI-MM reads in bypass path).");

            // Final clean run to confirm recovery path.
            axi_write32(8'h00, 32'h0000_0005);
            wait_done();
            expect_status(1'b1, 1'b1, 1'b0);
        end else begin
            // Gate B - Real integrated smoke.
            axi_read32(8'h00, rd);
            if (rd !== 32'h0000_0000) $fatal(1, "CTRL reset mismatch (Gate B): 0x%08h", rd);
            expect_status(1'b0, 1'b1, 1'b0);

            // Program seeds for KeyGen.
            for (i = 0; i < 8; i = i + 1) begin
                axi_write32(8'h10 + i*4, 32'h1234_0000 + i);
                axi_write32(8'h30 + i*4, 32'hABCD_0000 + i);
            end

            // Program DDR base pointers.
            axi_write32(8'h50, PK_BASE);
            axi_write32(8'h54, SK_BASE);
            axi_write32(8'h58, CT_BASE);
            axi_write32(8'h5C, SS_BASE);
            axi_write32(8'h60, M_BASE);

            // Prepare m for Encaps.
            for (i = 0; i < 32; i = i + 1) begin
                ddr_mem[M_BASE + i] = (i * 3 + 8'h21);
            end

            // KeyGen
            axi_write32(8'h00, 32'h0000_0001);
            expect_ctrl(2'd0);
            wait_done_limit(300000);
            expect_status(1'b1, 1'b1, 1'b0);
            axi_read32(8'h08, rd);
            if (rd == 32'd0) $fatal(1, "Gate B KeyGen cycles should be non-zero");

            // Encaps
            axi_write32(8'h00, 32'h0000_0003);
            expect_ctrl(2'd1);
            wait_done_limit(300000);
            expect_status(1'b1, 1'b1, 1'b0);
            for (i = 0; i < 32; i = i + 1) begin
                ss_enc[i] = ddr_mem[SS_BASE + i];
            end

            // Decaps (smoke path: no AXI-MM stall to isolate functional correctness first)
            axi_write32(8'h00, 32'h0000_0005);
            expect_ctrl(2'd2);
            wait_done_limit(500000);
            expect_status(1'b1, 1'b1, 1'b0);
            rd = 32'd0; // reuse as mismatch counter
            for (i = 0; i < 32; i = i + 1) begin
                ss_dec[i] = ddr_mem[SS_BASE + i];
                if (ss_dec[i] !== ss_enc[i]) begin
                    rd = rd + 32'd1;
                end
            end
            if (rd != 32'd0) begin
                dbg_sk_vs_ddr = 0;
                dbg_dk_vs_ddr = 0;
                dbg_ct_vs_ddr = 0;
                dbg_dk_vs_sk  = 0;
                dbg_pk_vs_sk_pk = 0;
                dbg_h_keygen_vs_encaps = 0;
                dbg_h_keygen_vs_sk = 0;
                for (i = 0; i < 2400; i = i + 1) begin
                    if (dut.sk_mem[i] !== ddr_mem[SK_BASE + i]) dbg_sk_vs_ddr = dbg_sk_vs_ddr + 1;
                    if (dut.dk_mem[i] !== ddr_mem[SK_BASE + i]) dbg_dk_vs_ddr = dbg_dk_vs_ddr + 1;
                    if (dut.dk_mem[i] !== dut.sk_mem[i])        dbg_dk_vs_sk  = dbg_dk_vs_sk  + 1;
                end
                for (i = 0; i < 1088; i = i + 1) begin
                    if (dut.ct_mem[i] !== ddr_mem[CT_BASE + i]) dbg_ct_vs_ddr = dbg_ct_vs_ddr + 1;
                end
                for (i = 0; i < 1184; i = i + 1) begin
                    if (dut.pk_mem[i] !== dut.sk_mem[1152 + i]) begin
                        dbg_pk_vs_sk_pk = dbg_pk_vs_sk_pk + 1;
                    end
                end
                for (i = 0; i < 32; i = i + 1) begin
                    if (probe_h_pk_reg[i] !== probe_encaps_h_buf[i]) begin
                        dbg_h_keygen_vs_encaps = dbg_h_keygen_vs_encaps + 1;
                    end
                    if (probe_h_pk_reg[i] !== dut.sk_mem[2336 + i]) begin
                        dbg_h_keygen_vs_sk = dbg_h_keygen_vs_sk + 1;
                    end
                end
                $display("DBG GateB top ss_enc[0..3]=%02x %02x %02x %02x", ss_enc[0], ss_enc[1], ss_enc[2], ss_enc[3]);
                $display("DBG GateB top ss_dec[0..3]=%02x %02x %02x %02x", ss_dec[0], ss_dec[1], ss_dec[2], ss_dec[3]);
                $display("DBG GateB h keygen[0..3]=%02x %02x %02x %02x encaps.h[0..3]=%02x %02x %02x %02x",
                         probe_h_pk_reg[0], probe_h_pk_reg[1],
                         probe_h_pk_reg[2], probe_h_pk_reg[3],
                         probe_encaps_h_buf[0], probe_encaps_h_buf[1],
                         probe_encaps_h_buf[2], probe_encaps_h_buf[3]);
                $display("DBG GateB dec match_reg=%0d xor_acc=%02x cmp_seen=%0d idx=%0d ct=%02x ct_prime=%02x enc_ct_count=%0d",
                         probe_dec_match_reg,
                         probe_dec_xor_acc,
                         probe_dec_cmp_seen,
                         probe_dec_cmp_idx,
                         probe_dec_ct_byte,
                         probe_dec_ct_prime_byte,
                         probe_dec_enc_ct_count);
                $display("DBG GateB dec k' [0..3]=%02x %02x %02x %02x  rej[0..3]=%02x %02x %02x %02x",
                         probe_dec_k_prime[0], probe_dec_k_prime[1],
                         probe_dec_k_prime[2], probe_dec_k_prime[3],
                         probe_dec_k_reject[0], probe_dec_k_reject[1],
                         probe_dec_k_reject[2], probe_dec_k_reject[3]);
                $display("DBG GateB dk/sk checkpoints: sk[0]=%02x dk[0]=%02x sk[1152]=%02x dk[1152]=%02x sk[2336]=%02x dk[2336]=%02x sk[2368]=%02x dk[2368]=%02x",
                         dut.sk_mem[0], dut.dk_mem[0],
                         dut.sk_mem[1152], dut.dk_mem[1152],
                         dut.sk_mem[2336], dut.dk_mem[2336],
                         dut.sk_mem[2368], dut.dk_mem[2368]);
                $display("DBG GateB pk/sk copy checkpoints: pk[0..3]=%02x %02x %02x %02x sk[1152..1155]=%02x %02x %02x %02x",
                         dut.pk_mem[0], dut.pk_mem[1], dut.pk_mem[2], dut.pk_mem[3],
                         dut.sk_mem[1152], dut.sk_mem[1153], dut.sk_mem[1154], dut.sk_mem[1155]);
                $display("DBG GateB h/z checkpoints: keygen.h[0..3]=%02x %02x %02x %02x sk[2336..2339]=%02x %02x %02x %02x z[2368..2371]=%02x %02x %02x %02x",
                         probe_h_pk_reg[0], probe_h_pk_reg[1],
                         probe_h_pk_reg[2], probe_h_pk_reg[3],
                         dut.sk_mem[2336], dut.sk_mem[2337], dut.sk_mem[2338], dut.sk_mem[2339],
                         dut.sk_mem[2368], dut.sk_mem[2369], dut.sk_mem[2370], dut.sk_mem[2371]);
                $display("DBG GateB mem consistency: sk_vs_ddr=%0d dk_vs_ddr=%0d ct_vs_ddr=%0d dk_vs_sk=%0d m[0]=%02x dec_m0=%02x",
                         dbg_sk_vs_ddr, dbg_dk_vs_ddr, dbg_ct_vs_ddr, dbg_dk_vs_sk,
                         ddr_mem[M_BASE + 0], probe_dec_m_out);
                $display("DBG GateB key consistency: pk_vs_skpk=%0d keygen_h_vs_encaps_h=%0d keygen_h_vs_sk_h=%0d",
                         dbg_pk_vs_sk_pk, dbg_h_keygen_vs_encaps, dbg_h_keygen_vs_sk);
                $fatal(1, "Gate B ss mismatch count=%0d", rd);
            end
        end

        $display("tb_ml_kem_top: PASS");
        $finish;
    end

endmodule
