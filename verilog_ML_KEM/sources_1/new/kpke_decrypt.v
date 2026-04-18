`timescale 1ns / 1ps

module kpke_decrypt (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    output reg          busy,
    output reg          done,

    // Input preload interface (byte-level)
    // in_sel = 0: dk_PKE (1152 bytes), 1: ct (1088 bytes)
    input  wire         in_we,
    input  wire         in_sel,
    input  wire [10:0]  in_addr,
    input  wire [7:0]   in_wdata,

    // Optional output readback interface (byte-level, message only: 32 bytes)
    input  wire         out_rd,
    input  wire [4:0]   out_addr,
    output reg  [7:0]   out_rdata,
    output reg          out_valid,

    // Optional streaming message output (32 bytes)
    output wire         msg_we,
    output wire [4:0]   msg_addr,
    output wire [7:0]   msg_dout,

    // Packed message output (m[0] at bits [7:0])
    output reg  [255:0] m_out
);

    // =============================================================
    // FSM states
    // =============================================================
    localparam [5:0] S_IDLE               = 6'd0;

    localparam [5:0] S_DECODE_SK_START    = 6'd1;
    localparam [5:0] S_DECODE_SK_WAIT     = 6'd2;

    localparam [5:0] S_DECOMP_U_START     = 6'd3;
    localparam [5:0] S_DECOMP_U_WAIT      = 6'd4;
    localparam [5:0] S_DECOMP_V_START     = 6'd5;
    localparam [5:0] S_DECOMP_V_WAIT      = 6'd6;

    localparam [5:0] S_NTT_LOAD_LOOP      = 6'd7;
    localparam [5:0] S_NTT_START          = 6'd8;
    localparam [5:0] S_NTT_WAIT           = 6'd9;
    localparam [5:0] S_NTT_READ_REQ       = 6'd10;
    localparam [5:0] S_NTT_READ_CAP       = 6'd11;

    localparam [5:0] S_PW_LOAD_A_LOOP     = 6'd12;
    localparam [5:0] S_PW_LOAD_B_LOOP     = 6'd13;
    localparam [5:0] S_PW_START           = 6'd14;
    localparam [5:0] S_PW_WAIT            = 6'd15;
    localparam [5:0] S_PW_READ_REQ        = 6'd16;
    localparam [5:0] S_PW_READ_CAP        = 6'd17;

    localparam [5:0] S_ADDACC_LOAD_A_LOOP = 6'd18;
    localparam [5:0] S_ADDACC_LOAD_B_LOOP = 6'd19;
    localparam [5:0] S_ADDACC_START       = 6'd20;
    localparam [5:0] S_ADDACC_WAIT        = 6'd21;
    localparam [5:0] S_ADDACC_READ_REQ    = 6'd22;
    localparam [5:0] S_ADDACC_READ_CAP    = 6'd23;

    localparam [5:0] S_INTT_LOAD_LOOP     = 6'd24;
    localparam [5:0] S_INTT_START         = 6'd25;
    localparam [5:0] S_INTT_WAIT          = 6'd26;
    localparam [5:0] S_INTT_READ_REQ      = 6'd27;
    localparam [5:0] S_INTT_READ_CAP      = 6'd28;

    localparam [5:0] S_SUB_LOAD_A_LOOP    = 6'd29;
    localparam [5:0] S_SUB_LOAD_B_LOOP    = 6'd30;
    localparam [5:0] S_SUB_START          = 6'd31;
    localparam [5:0] S_SUB_WAIT           = 6'd32;
    localparam [5:0] S_SUB_READ_REQ       = 6'd33;
    localparam [5:0] S_SUB_READ_CAP       = 6'd34;

    localparam [5:0] S_COMP_START         = 6'd35;
    localparam [5:0] S_COMP_WAIT          = 6'd36;

    localparam [5:0] S_DONE               = 6'd37;

    // Prefetch states for synchronous internal memory reads
    localparam [5:0] S_NTT_LOAD_PREF      = 6'd38;
    localparam [5:0] S_PW_LOAD_A_PREF     = 6'd39;
    localparam [5:0] S_PW_LOAD_B_PREF     = 6'd40;
    localparam [5:0] S_ADDACC_LOAD_A_PREF = 6'd41;
    localparam [5:0] S_ADDACC_LOAD_B_PREF = 6'd42;
    localparam [5:0] S_INTT_LOAD_PREF     = 6'd43;
    localparam [5:0] S_SUB_LOAD_A_PREF    = 6'd44;
    localparam [5:0] S_SUB_LOAD_B_PREF    = 6'd45;
    localparam [5:0] S_COMP_PREF          = 6'd46;

    reg [5:0] state;

    // =============================================================
    // Input / Output byte buffers
    // =============================================================
    (* ram_style = "block" *) reg [7:0] dk_buf  [0:1151];
    (* ram_style = "block" *) reg [7:0] ct_buf  [0:1087];
    reg [7:0] msg_buf [0:31];

    // =============================================================
    // Internal memories
    // =============================================================
    // Banked memories for dual-coefficient writes and sync reads
    (* ram_style = "block" *) reg [15:0] s_hat_mem0  [0:383];
    (* ram_style = "block" *) reg [15:0] s_hat_mem1  [0:383];
    (* ram_style = "block" *) reg [15:0] u_poly_mem0 [0:383];
    (* ram_style = "block" *) reg [15:0] u_poly_mem1 [0:383];
    (* ram_style = "block" *) reg [15:0] v_mem0      [0:127];
    (* ram_style = "block" *) reg [15:0] v_mem1      [0:127];
    (* ram_style = "block" *) reg [15:0] diff_mem0   [0:127];
    (* ram_style = "block" *) reg [15:0] diff_mem1   [0:127];

    // Single-write memories with synchronous read datapaths
    (* ram_style = "block" *) reg [15:0] u_hat_mem   [0:767];
    (* ram_style = "block" *) reg [15:0] acc_mem     [0:255];
    (* ram_style = "block" *) reg [15:0] tmp_mem     [0:255];
    (* ram_style = "block" *) reg [15:0] w_mem       [0:255];

    // =============================================================
    // Control registers / indices
    // =============================================================
    reg [1:0] sk_idx;
    reg [1:0] dec_u_idx;
    reg       dec_phase_v;

    reg [1:0] ntt_idx;
    reg [1:0] pw_idx;

    reg [7:0] coeff_idx;
    wire [7:0] coeff_idx_next;
    integer clr_i;

    reg [15:0] s_hat_rd_a0, s_hat_rd_a1;
    reg [15:0] u_poly_rd_a0, u_poly_rd_a1;
    reg [15:0] u_hat_rdata;
    reg [15:0] v_rd_a0, v_rd_a1;
    reg [15:0] acc_rdata;
    reg [15:0] tmp_rdata;
    reg [15:0] w_rdata;
    reg [15:0] diff_rd_a0, diff_rd_a1;

    wire [8:0] s_hat_rpair_addr;
    wire [8:0] u_poly_rpair_addr;
    wire [9:0] u_hat_raddr;
    wire [6:0] v_rpair_addr;
    wire [7:0] acc_raddr;
    wire [7:0] tmp_raddr;
    wire [7:0] w_raddr;
    wire [6:0] diff_rpair_addr;

    wire [15:0] s_hat_load_din;
    wire [15:0] u_poly_load_din;
    wire [15:0] v_load_din;

    // =============================================================
    // 1) poly_frombytes (decode s_hat)
    // =============================================================
    wire        fromb_start;
    wire        fromb_done;
    wire [8:0]  fromb_byte_addr;
    wire [7:0]  fromb_byte_din;
    wire        fromb_coeff_we;
    wire [6:0]  fromb_coeff_addr;
    wire [15:0] fromb_coeff_a0;
    wire [15:0] fromb_coeff_a1;

    wire [10:0] fromb_base_addr = (sk_idx == 2'd0) ? 11'd0 :
                                  (sk_idx == 2'd1) ? 11'd384 : 11'd768;
    wire [10:0] fromb_abs_addr  = fromb_base_addr + {2'b00, fromb_byte_addr};

    assign fromb_start    = (state == S_DECODE_SK_START);

    poly_frombytes u_frombytes (
        .clk(clk),
        .rst_n(rst_n),
        .start(fromb_start),
        .done(fromb_done),
        .byte_addr(fromb_byte_addr),
        .byte_din(fromb_byte_din),
        .coeff_we(fromb_coeff_we),
        .coeff_addr(fromb_coeff_addr),
        .coeff_a0(fromb_coeff_a0),
        .coeff_a1(fromb_coeff_a1)
    );

    // =============================================================
    // 2) poly_decompress (u, v)
    // =============================================================
    wire        decomp_start;
    wire        decomp_done;
    wire [1:0]  decomp_d_sel;
    wire [8:0]  decomp_byte_addr;
    wire [7:0]  decomp_byte_din;
    wire        decomp_coeff_we;
    wire [6:0]  decomp_coeff_addr;
    wire [15:0] decomp_coeff_a0;
    wire [15:0] decomp_coeff_a1;

    wire [10:0] decomp_base_addr = dec_phase_v ? 11'd960 :
                                   (dec_u_idx == 2'd0) ? 11'd0 :
                                   (dec_u_idx == 2'd1) ? 11'd320 : 11'd640;
    wire [10:0] decomp_abs_addr  = decomp_base_addr + {2'b00, decomp_byte_addr};

    assign decomp_start    = (state == S_DECOMP_U_START) || (state == S_DECOMP_V_START);
    assign decomp_d_sel    = dec_phase_v ? 2'b01 : 2'b10; // v:d4, u:d10

    poly_decompress u_decompress (
        .clk(clk),
        .rst_n(rst_n),
        .start(decomp_start),
        .d_sel(decomp_d_sel),
        .done(decomp_done),
        .byte_addr(decomp_byte_addr),
        .byte_din(decomp_byte_din),
        .coeff_we(decomp_coeff_we),
        .coeff_addr(decomp_coeff_addr),
        .coeff_a0(decomp_coeff_a0),
        .coeff_a1(decomp_coeff_a1)
    );

    assign coeff_idx_next = (coeff_idx == 8'd255) ? 8'd255 : (coeff_idx + 8'd1);

    assign s_hat_rpair_addr = (state == S_PW_LOAD_A_PREF) ? {pw_idx, 7'd0} :
                              (state == S_PW_LOAD_A_LOOP) ? {pw_idx, coeff_idx_next[7:1]} :
                              9'd0;
    assign u_poly_rpair_addr = (state == S_NTT_LOAD_PREF) ? {ntt_idx, 7'd0} :
                               (state == S_NTT_LOAD_LOOP) ? {ntt_idx, coeff_idx_next[7:1]} :
                               9'd0;
    assign u_hat_raddr = (state == S_PW_LOAD_B_PREF) ? {pw_idx, 8'd0} :
                         (state == S_PW_LOAD_B_LOOP) ? {pw_idx, coeff_idx_next} :
                         10'd0;
    assign v_rpair_addr = (state == S_SUB_LOAD_A_PREF) ? 7'd0 :
                          (state == S_SUB_LOAD_A_LOOP) ? coeff_idx_next[7:1] :
                          7'd0;
    assign acc_raddr = ((state == S_ADDACC_LOAD_A_PREF) || (state == S_INTT_LOAD_PREF)) ? 8'd0 :
                       ((state == S_ADDACC_LOAD_A_LOOP) || (state == S_INTT_LOAD_LOOP)) ? coeff_idx_next :
                       8'd0;
    assign tmp_raddr = (state == S_ADDACC_LOAD_B_PREF) ? 8'd0 :
                       (state == S_ADDACC_LOAD_B_LOOP) ? coeff_idx_next :
                       8'd0;
    assign w_raddr = (state == S_SUB_LOAD_B_PREF) ? 8'd0 :
                     (state == S_SUB_LOAD_B_LOOP) ? coeff_idx_next :
                     8'd0;
    assign s_hat_load_din = coeff_idx[0] ? s_hat_rd_a1 : s_hat_rd_a0;
    assign u_poly_load_din = coeff_idx[0] ? u_poly_rd_a1 : u_poly_rd_a0;
    assign v_load_din = coeff_idx[0] ? v_rd_a1 : v_rd_a0;

    // =============================================================
    // 3) ntt_top (for u -> u_hat)
    // =============================================================
    wire        ntt_start;
    wire        ntt_done;
    wire        ntt_host_we;
    wire [7:0]  ntt_host_addr;
    wire [15:0] ntt_host_din;
    wire [15:0] ntt_host_dout;

    assign ntt_start     = (state == S_NTT_START);
    assign ntt_host_we   = (state == S_NTT_LOAD_LOOP);
    assign ntt_host_addr = ((state == S_NTT_LOAD_LOOP) || (state == S_NTT_READ_REQ)) ? coeff_idx : 8'd0;
    assign ntt_host_din  = u_poly_load_din;

    ntt_top u_ntt (
        .clk(clk),
        .rst_n(rst_n),
        .start(ntt_start),
        .done(ntt_done),
        .host_we(ntt_host_we),
        .host_addr(ntt_host_addr),
        .host_din(ntt_host_din),
        .host_dout(ntt_host_dout)
    );

    // =============================================================
    // 4) poly_pointwise_top (s_hat[i] * u_hat[i])
    // =============================================================
    wire        pw_start;
    wire        pw_done;
    wire        pw_host_sel;
    wire        pw_host_we;
    wire [7:0]  pw_host_addr;
    wire [15:0] pw_host_din;
    wire [15:0] pw_host_dout;

    assign pw_start = (state == S_PW_START);

    assign pw_host_sel = (state == S_PW_LOAD_B_LOOP) ? 1'b1 : 1'b0;
    assign pw_host_we  = (state == S_PW_LOAD_A_LOOP) || (state == S_PW_LOAD_B_LOOP);

    assign pw_host_addr = ((state == S_PW_LOAD_A_LOOP) ||
                           (state == S_PW_LOAD_B_LOOP) ||
                           (state == S_PW_READ_REQ)) ? coeff_idx : 8'd0;

    assign pw_host_din = (state == S_PW_LOAD_A_LOOP) ? s_hat_load_din :
                         (state == S_PW_LOAD_B_LOOP) ? u_hat_rdata :
                         16'd0;

    poly_pointwise_top u_pw (
        .clk(clk),
        .rst_n(rst_n),
        .start(pw_start),
        .done(pw_done),
        .host_sel(pw_host_sel),
        .host_we(pw_host_we),
        .host_addr(pw_host_addr),
        .host_din(pw_host_din),
        .host_dout(pw_host_dout)
    );

    // =============================================================
    // 5) poly_add_sub_top
    //    - accumulate pointwise results (ADD)
    //    - final v - w subtraction (SUB)
    // =============================================================
    wire        add_start;
    wire        add_is_sub;
    wire        add_done;
    wire        add_host_sel;
    wire        add_host_we;
    wire [7:0]  add_host_addr;
    wire [15:0] add_host_din;
    wire [15:0] add_host_dout;

    assign add_start = (state == S_ADDACC_START) || (state == S_SUB_START);

    assign add_is_sub = (state == S_SUB_LOAD_A_LOOP) ||
                        (state == S_SUB_LOAD_B_LOOP) ||
                        (state == S_SUB_START)       ||
                        (state == S_SUB_WAIT)        ||
                        (state == S_SUB_READ_REQ)    ||
                        (state == S_SUB_READ_CAP);

    assign add_host_sel = (state == S_ADDACC_LOAD_B_LOOP) || (state == S_SUB_LOAD_B_LOOP);

    assign add_host_we = (state == S_ADDACC_LOAD_A_LOOP) ||
                         (state == S_ADDACC_LOAD_B_LOOP) ||
                         (state == S_SUB_LOAD_A_LOOP)    ||
                         (state == S_SUB_LOAD_B_LOOP);

    assign add_host_addr = ((state == S_ADDACC_LOAD_A_LOOP) ||
                            (state == S_ADDACC_LOAD_B_LOOP) ||
                            (state == S_ADDACC_READ_REQ)    ||
                            (state == S_SUB_LOAD_A_LOOP)    ||
                            (state == S_SUB_LOAD_B_LOOP)    ||
                            (state == S_SUB_READ_REQ)) ? coeff_idx : 8'd0;

    assign add_host_din = (state == S_ADDACC_LOAD_A_LOOP) ? acc_rdata :
                          (state == S_ADDACC_LOAD_B_LOOP) ? tmp_rdata :
                          (state == S_SUB_LOAD_A_LOOP)    ? v_load_din :
                          (state == S_SUB_LOAD_B_LOOP)    ? w_rdata :
                          16'd0;

    poly_add_sub_top u_add_sub (
        .clk(clk),
        .rst_n(rst_n),
        .start(add_start),
        .is_sub(add_is_sub),
        .done(add_done),
        .host_sel(add_host_sel),
        .host_we(add_host_we),
        .host_addr(add_host_addr),
        .host_din(add_host_din),
        .host_dout(add_host_dout)
    );

    // =============================================================
    // 6) inv_ntt_top (w = INTT(acc))
    // =============================================================
    wire        intt_start;
    wire        intt_done;
    wire        intt_host_we;
    wire [7:0]  intt_host_addr;
    wire [15:0] intt_host_din;
    wire [15:0] intt_host_dout;

    assign intt_start     = (state == S_INTT_START);
    assign intt_host_we   = (state == S_INTT_LOAD_LOOP);
    assign intt_host_addr = ((state == S_INTT_LOAD_LOOP) || (state == S_INTT_READ_REQ)) ? coeff_idx : 8'd0;
    assign intt_host_din  = acc_rdata;

    inv_ntt_top u_inv_ntt (
        .clk(clk),
        .rst_n(rst_n),
        .start(intt_start),
        .done(intt_done),
        .host_we(intt_host_we),
        .host_addr(intt_host_addr),
        .host_din(intt_host_din),
        .host_dout(intt_host_dout)
    );

    // =============================================================
    // 7) poly_compress (d=1) -> message
    // =============================================================
    wire        comp_start;
    wire        comp_done;
    wire [6:0]  comp_coeff_addr;
    wire [15:0] comp_coeff_a0;
    wire [15:0] comp_coeff_a1;
    wire        comp_byte_we;
    wire [8:0]  comp_byte_addr;
    wire [7:0]  comp_byte_dout;

    assign diff_rpair_addr = (state == S_COMP_PREF) ? 7'd0 :
                             ((state == S_COMP_START) || (state == S_COMP_WAIT)) ? comp_coeff_addr :
                             7'd0;
    assign comp_start    = (state == S_COMP_START);

    poly_compress u_compress (
        .clk(clk),
        .rst_n(rst_n),
        .start(comp_start),
        .d_sel(2'b00), // d=1
        .done(comp_done),
        .coeff_addr(comp_coeff_addr),
        .coeff_a0(comp_coeff_a0),
        .coeff_a1(comp_coeff_a1),
        .byte_we(comp_byte_we),
        .byte_addr(comp_byte_addr),
        .byte_dout(comp_byte_dout)
    );

    assign msg_we   = (state == S_COMP_WAIT) ? comp_byte_we : 1'b0;
    assign msg_addr = comp_byte_addr[4:0];
    assign msg_dout = comp_byte_dout;

    // =============================================================
    // Synchronous read adapters for byte/coeff memories
    // (poly_frombytes / poly_decompress / poly_compress expect 1-cycle
    // RAM read latency on their input interfaces)
    // =============================================================
    reg [7:0]  fromb_byte_din_r;
    reg [7:0]  decomp_byte_din_r;

    assign fromb_byte_din = fromb_byte_din_r;
    assign decomp_byte_din = decomp_byte_din_r;
    assign comp_coeff_a0 = diff_rd_a0;
    assign comp_coeff_a1 = diff_rd_a1;

    // Byte buffers: keep RAM path fully synchronous (no async reset on RAM access)
    // to preserve BRAM inference for dk_buf/ct_buf.
    always @(posedge clk) begin
        if (in_we && !busy) begin
            if (!in_sel) begin
                if (in_addr < 11'd1152) begin
                    dk_buf[in_addr] <= in_wdata;
                end
            end else begin
                if (in_addr < 11'd1088) begin
                    ct_buf[in_addr] <= in_wdata;
                end
            end
        end
        fromb_byte_din_r <= dk_buf[fromb_abs_addr];
        decomp_byte_din_r <= ct_buf[decomp_abs_addr];
    end

    // =============================================================
    // Internal memory processes (separated from FSM control)
    // =============================================================
    always @(posedge clk) begin
        if (!rst_n) begin
            s_hat_rd_a0 <= 16'd0;
            s_hat_rd_a1 <= 16'd0;
        end else begin
            s_hat_rd_a0 <= s_hat_mem0[s_hat_rpair_addr];
            s_hat_rd_a1 <= s_hat_mem1[s_hat_rpair_addr];
            if (fromb_coeff_we) begin
                s_hat_mem0[{sk_idx, fromb_coeff_addr}] <= fromb_coeff_a0;
                s_hat_mem1[{sk_idx, fromb_coeff_addr}] <= fromb_coeff_a1;
            end
        end
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            u_poly_rd_a0 <= 16'd0;
            u_poly_rd_a1 <= 16'd0;
        end else begin
            u_poly_rd_a0 <= u_poly_mem0[u_poly_rpair_addr];
            u_poly_rd_a1 <= u_poly_mem1[u_poly_rpair_addr];
            if (decomp_coeff_we && !dec_phase_v) begin
                u_poly_mem0[{dec_u_idx, decomp_coeff_addr}] <= decomp_coeff_a0;
                u_poly_mem1[{dec_u_idx, decomp_coeff_addr}] <= decomp_coeff_a1;
            end
        end
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            u_hat_rdata <= 16'd0;
        end else begin
            u_hat_rdata <= u_hat_mem[u_hat_raddr];
            if (state == S_NTT_READ_CAP) begin
                u_hat_mem[{ntt_idx, coeff_idx}] <= ntt_host_dout;
            end
        end
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            v_rd_a0 <= 16'd0;
            v_rd_a1 <= 16'd0;
        end else begin
            v_rd_a0 <= v_mem0[v_rpair_addr];
            v_rd_a1 <= v_mem1[v_rpair_addr];
            if (decomp_coeff_we && dec_phase_v) begin
                v_mem0[decomp_coeff_addr] <= decomp_coeff_a0;
                v_mem1[decomp_coeff_addr] <= decomp_coeff_a1;
            end
        end
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            acc_rdata <= 16'd0;
        end else begin
            acc_rdata <= acc_mem[acc_raddr];
            if ((state == S_PW_READ_CAP) && (pw_idx == 2'd0)) begin
                acc_mem[coeff_idx] <= pw_host_dout;
            end else if (state == S_ADDACC_READ_CAP) begin
                acc_mem[coeff_idx] <= add_host_dout;
            end
        end
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            tmp_rdata <= 16'd0;
        end else begin
            tmp_rdata <= tmp_mem[tmp_raddr];
            if ((state == S_PW_READ_CAP) && (pw_idx != 2'd0)) begin
                tmp_mem[coeff_idx] <= pw_host_dout;
            end
        end
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            w_rdata <= 16'd0;
        end else begin
            w_rdata <= w_mem[w_raddr];
            if (state == S_INTT_READ_CAP) begin
                w_mem[coeff_idx] <= intt_host_dout;
            end
        end
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            diff_rd_a0 <= 16'd0;
            diff_rd_a1 <= 16'd0;
        end else begin
            diff_rd_a0 <= diff_mem0[diff_rpair_addr];
            diff_rd_a1 <= diff_mem1[diff_rpair_addr];
            if (state == S_SUB_READ_CAP) begin
                if (coeff_idx[0]) begin
                    diff_mem1[coeff_idx[7:1]] <= add_host_dout;
                end else begin
                    diff_mem0[coeff_idx[7:1]] <= add_host_dout;
                end
            end
        end
    end

    // =============================================================
    // Main FSM
    // =============================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state       <= S_IDLE;
            busy        <= 1'b0;
            done        <= 1'b0;
            m_out       <= 256'd0;
            out_rdata   <= 8'd0;
            out_valid   <= 1'b0;
            for (clr_i = 0; clr_i < 32; clr_i = clr_i + 1) begin
                msg_buf[clr_i] <= 8'd0;
            end

            sk_idx      <= 2'd0;
            dec_u_idx   <= 2'd0;
            dec_phase_v <= 1'b0;
            ntt_idx     <= 2'd0;
            pw_idx      <= 2'd0;
            coeff_idx   <= 8'd0;
        end else begin
            done      <= 1'b0;
            out_valid <= 1'b0;

            if (out_rd) begin
                out_valid <= 1'b1;
                if (out_addr <= 5'd31) out_rdata <= msg_buf[out_addr];
                else                   out_rdata <= 8'd0;
            end

            if ((state == S_COMP_WAIT) && comp_byte_we && (comp_byte_addr < 9'd32)) begin
                m_out[comp_byte_addr*8 +: 8] <= comp_byte_dout;
                msg_buf[comp_byte_addr[4:0]] <= comp_byte_dout;
            end

            // -----------------------------------------------------
            // FSM transition
            // -----------------------------------------------------
            case (state)
                S_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        busy        <= 1'b1;
                        m_out       <= 256'd0;
                        for (clr_i = 0; clr_i < 32; clr_i = clr_i + 1) begin
                            msg_buf[clr_i] <= 8'd0;
                        end
                        sk_idx      <= 2'd0;
                        dec_u_idx   <= 2'd0;
                        dec_phase_v <= 1'b0;
                        ntt_idx     <= 2'd0;
                        pw_idx      <= 2'd0;
                        coeff_idx   <= 8'd0;
                        state       <= S_DECODE_SK_START;
                    end
                end

                // Decode sk polynomials
                S_DECODE_SK_START: begin
                    state <= S_DECODE_SK_WAIT;
                end

                S_DECODE_SK_WAIT: begin
                    if (fromb_done) begin
                        if (sk_idx == 2'd2) begin
                            dec_u_idx   <= 2'd0;
                            dec_phase_v <= 1'b0;
                            state       <= S_DECOMP_U_START;
                        end else begin
                            sk_idx <= sk_idx + 2'd1;
                            state  <= S_DECODE_SK_START;
                        end
                    end
                end

                // Decompress c1 -> u[0..2]
                S_DECOMP_U_START: begin
                    dec_phase_v <= 1'b0;
                    state       <= S_DECOMP_U_WAIT;
                end

                S_DECOMP_U_WAIT: begin
                    if (decomp_done) begin
                        if (dec_u_idx == 2'd2) begin
                            dec_phase_v <= 1'b1;
                            state       <= S_DECOMP_V_START;
                        end else begin
                            dec_u_idx <= dec_u_idx + 2'd1;
                            state     <= S_DECOMP_U_START;
                        end
                    end
                end

                // Decompress c2 -> v
                S_DECOMP_V_START: begin
                    dec_phase_v <= 1'b1;
                    state       <= S_DECOMP_V_WAIT;
                end

                S_DECOMP_V_WAIT: begin
                    if (decomp_done) begin
                        ntt_idx   <= 2'd0;
                        coeff_idx <= 8'd0;
                        state     <= S_NTT_LOAD_PREF;
                    end
                end

                // NTT(u[i]) loop
                S_NTT_LOAD_PREF: begin
                    coeff_idx <= 8'd0;
                    state     <= S_NTT_LOAD_LOOP;
                end

                S_NTT_LOAD_LOOP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state     <= S_NTT_START;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_NTT_START: begin
                    state <= S_NTT_WAIT;
                end

                S_NTT_WAIT: begin
                    if (ntt_done) begin
                        coeff_idx <= 8'd0;
                        state     <= S_NTT_READ_REQ;
                    end
                end

                S_NTT_READ_REQ: begin
                    state <= S_NTT_READ_CAP;
                end

                S_NTT_READ_CAP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        if (ntt_idx == 2'd2) begin
                            pw_idx <= 2'd0;
                            state  <= S_PW_LOAD_A_PREF;
                        end else begin
                            ntt_idx <= ntt_idx + 2'd1;
                            state   <= S_NTT_LOAD_PREF;
                        end
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state     <= S_NTT_READ_REQ;
                    end
                end

                // Pointwise s_hat[i] * u_hat[i]
                S_PW_LOAD_A_PREF: begin
                    coeff_idx <= 8'd0;
                    state     <= S_PW_LOAD_A_LOOP;
                end

                S_PW_LOAD_A_LOOP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state     <= S_PW_LOAD_B_PREF;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_PW_LOAD_B_PREF: begin
                    coeff_idx <= 8'd0;
                    state     <= S_PW_LOAD_B_LOOP;
                end

                S_PW_LOAD_B_LOOP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state     <= S_PW_START;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_PW_START: begin
                    state <= S_PW_WAIT;
                end

                S_PW_WAIT: begin
                    if (pw_done) begin
                        coeff_idx <= 8'd0;
                        state     <= S_PW_READ_REQ;
                    end
                end

                S_PW_READ_REQ: begin
                    state <= S_PW_READ_CAP;
                end

                S_PW_READ_CAP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        if (pw_idx == 2'd0) begin
                            pw_idx <= 2'd1;
                            state  <= S_PW_LOAD_A_PREF;
                        end else begin
                            state <= S_ADDACC_LOAD_A_PREF;
                        end
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state     <= S_PW_READ_REQ;
                    end
                end

                // acc += tmp for i=1,2
                S_ADDACC_LOAD_A_PREF: begin
                    coeff_idx <= 8'd0;
                    state     <= S_ADDACC_LOAD_A_LOOP;
                end

                S_ADDACC_LOAD_A_LOOP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state     <= S_ADDACC_LOAD_B_PREF;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_ADDACC_LOAD_B_PREF: begin
                    coeff_idx <= 8'd0;
                    state     <= S_ADDACC_LOAD_B_LOOP;
                end

                S_ADDACC_LOAD_B_LOOP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state     <= S_ADDACC_START;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_ADDACC_START: begin
                    state <= S_ADDACC_WAIT;
                end

                S_ADDACC_WAIT: begin
                    if (add_done) begin
                        coeff_idx <= 8'd0;
                        state     <= S_ADDACC_READ_REQ;
                    end
                end

                S_ADDACC_READ_REQ: begin
                    state <= S_ADDACC_READ_CAP;
                end

                S_ADDACC_READ_CAP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        if (pw_idx == 2'd2) begin
                            state <= S_INTT_LOAD_PREF;
                        end else begin
                            pw_idx <= pw_idx + 2'd1;
                            state  <= S_PW_LOAD_A_PREF;
                        end
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state     <= S_ADDACC_READ_REQ;
                    end
                end

                // INTT(acc) -> w
                S_INTT_LOAD_PREF: begin
                    coeff_idx <= 8'd0;
                    state     <= S_INTT_LOAD_LOOP;
                end

                S_INTT_LOAD_LOOP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state     <= S_INTT_START;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_INTT_START: begin
                    state <= S_INTT_WAIT;
                end

                S_INTT_WAIT: begin
                    if (intt_done) begin
                        coeff_idx <= 8'd0;
                        state     <= S_INTT_READ_REQ;
                    end
                end

                S_INTT_READ_REQ: begin
                    state <= S_INTT_READ_CAP;
                end

                S_INTT_READ_CAP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state     <= S_SUB_LOAD_A_PREF;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state     <= S_INTT_READ_REQ;
                    end
                end

                // diff = v - w
                S_SUB_LOAD_A_PREF: begin
                    coeff_idx <= 8'd0;
                    state     <= S_SUB_LOAD_A_LOOP;
                end

                S_SUB_LOAD_A_LOOP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state     <= S_SUB_LOAD_B_PREF;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_SUB_LOAD_B_PREF: begin
                    coeff_idx <= 8'd0;
                    state     <= S_SUB_LOAD_B_LOOP;
                end

                S_SUB_LOAD_B_LOOP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state     <= S_SUB_START;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_SUB_START: begin
                    state <= S_SUB_WAIT;
                end

                S_SUB_WAIT: begin
                    if (add_done) begin
                        coeff_idx <= 8'd0;
                        state     <= S_SUB_READ_REQ;
                    end
                end

                S_SUB_READ_REQ: begin
                    state <= S_SUB_READ_CAP;
                end

                S_SUB_READ_CAP: begin
                    if (coeff_idx == 8'd255) begin
                        state <= S_COMP_PREF;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state     <= S_SUB_READ_REQ;
                    end
                end

                // Compress_1(diff) -> m
                S_COMP_PREF: begin
                    state <= S_COMP_START;
                end

                S_COMP_START: begin
                    state <= S_COMP_WAIT;
                end

                S_COMP_WAIT: begin
                    if (comp_done) begin
                        state <= S_DONE;
                    end
                end

                S_DONE: begin
                    busy  <= 1'b0;
                    done  <= 1'b1;
                    state <= S_IDLE;
                end

                default: begin
                    state <= S_IDLE;
                end
            endcase
        end
    end

endmodule
