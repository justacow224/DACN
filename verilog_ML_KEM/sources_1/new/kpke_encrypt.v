`timescale 1ns / 1ps

module kpke_encrypt (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    output reg          busy,
    output reg          done,

    // Input preload interface
    // in_sel = 0: ek (1184 bytes)
    // in_sel = 1: m  (32 bytes)
    // in_sel = 2: r  (32 bytes)
    input  wire         in_we,
    input  wire [1:0]   in_sel,
    input  wire [10:0]  in_addr,
    input  wire [7:0]   in_wdata,

    // Output readback interface
    input  wire         out_rd,
    input  wire [10:0]  out_addr,
    output reg  [7:0]   out_rdata,
    output reg          out_valid,

    // Optional streaming ciphertext output
    output wire         ct_we,
    output wire [10:0]  ct_addr,
    output wire [7:0]   ct_dout
);

    // =============================================================
    // FSM states
    // =============================================================
    localparam [7:0] S_IDLE              = 8'd0;

    localparam [7:0] S_DECODE_EK_START   = 8'd1;
    localparam [7:0] S_DECODE_EK_WAIT    = 8'd2;

    localparam [7:0] S_NOISE_INIT        = 8'd3;
    localparam [7:0] S_PRF_ABSORB        = 8'd4;
    localparam [7:0] S_PRF_FINAL         = 8'd5;
    localparam [7:0] S_PRF_WAIT          = 8'd6;
    localparam [7:0] S_CBD_START         = 8'd7;
    localparam [7:0] S_CBD_WAIT          = 8'd8;
    localparam [7:0] S_NTT_LOAD          = 8'd9;
    localparam [7:0] S_NTT_START         = 8'd10;
    localparam [7:0] S_NTT_WAIT          = 8'd11;
    localparam [7:0] S_NTT_READ_REQ      = 8'd12;
    localparam [7:0] S_NTT_READ_CAP      = 8'd13;

    localparam [7:0] S_FROMMSG_START     = 8'd14;
    localparam [7:0] S_FROMMSG_WAIT      = 8'd15;

    localparam [7:0] S_U_INIT            = 8'd20;
    localparam [7:0] S_U_XOF_INIT        = 8'd21;
    localparam [7:0] S_U_XOF_ABSORB      = 8'd22;
    localparam [7:0] S_U_XOF_FINAL       = 8'd23;
    localparam [7:0] S_U_PARSE_START     = 8'd24;
    localparam [7:0] S_U_PARSE_WAIT      = 8'd25;

    localparam [7:0] S_U_PW_LOAD_A       = 8'd26;
    localparam [7:0] S_U_PW_LOAD_B       = 8'd27;
    localparam [7:0] S_U_PW_START        = 8'd28;
    localparam [7:0] S_U_PW_WAIT         = 8'd29;
    localparam [7:0] S_U_PW_READ_REQ     = 8'd30;
    localparam [7:0] S_U_PW_READ_CAP     = 8'd31;

    localparam [7:0] S_U_COPY_TMP        = 8'd32;

    localparam [7:0] S_U_ADDACC_LOAD_A   = 8'd33;
    localparam [7:0] S_U_ADDACC_LOAD_B   = 8'd34;
    localparam [7:0] S_U_ADDACC_START    = 8'd35;
    localparam [7:0] S_U_ADDACC_WAIT     = 8'd36;
    localparam [7:0] S_U_ADDACC_READ_REQ = 8'd37;
    localparam [7:0] S_U_ADDACC_READ_CAP = 8'd38;

    localparam [7:0] S_U_INTT_LOAD       = 8'd39;
    localparam [7:0] S_U_INTT_START      = 8'd40;
    localparam [7:0] S_U_INTT_WAIT       = 8'd41;
    localparam [7:0] S_U_INTT_READ_REQ   = 8'd42;
    localparam [7:0] S_U_INTT_READ_CAP   = 8'd43;

    localparam [7:0] S_U_ADDE1_LOAD_A    = 8'd44;
    localparam [7:0] S_U_ADDE1_LOAD_B    = 8'd45;
    localparam [7:0] S_U_ADDE1_START     = 8'd46;
    localparam [7:0] S_U_ADDE1_WAIT      = 8'd47;
    localparam [7:0] S_U_ADDE1_READ_REQ  = 8'd48;
    localparam [7:0] S_U_ADDE1_READ_CAP  = 8'd49;

    localparam [7:0] S_V_INIT            = 8'd60;
    localparam [7:0] S_V_PW_LOAD_A       = 8'd61;
    localparam [7:0] S_V_PW_LOAD_B       = 8'd62;
    localparam [7:0] S_V_PW_START        = 8'd63;
    localparam [7:0] S_V_PW_WAIT         = 8'd64;
    localparam [7:0] S_V_PW_READ_REQ     = 8'd65;
    localparam [7:0] S_V_PW_READ_CAP     = 8'd66;

    localparam [7:0] S_V_COPY_TMP        = 8'd67;

    localparam [7:0] S_V_ADDACC_LOAD_A   = 8'd68;
    localparam [7:0] S_V_ADDACC_LOAD_B   = 8'd69;
    localparam [7:0] S_V_ADDACC_START    = 8'd70;
    localparam [7:0] S_V_ADDACC_WAIT     = 8'd71;
    localparam [7:0] S_V_ADDACC_READ_REQ = 8'd72;
    localparam [7:0] S_V_ADDACC_READ_CAP = 8'd73;

    localparam [7:0] S_V_INTT_LOAD       = 8'd74;
    localparam [7:0] S_V_INTT_START      = 8'd75;
    localparam [7:0] S_V_INTT_WAIT       = 8'd76;
    localparam [7:0] S_V_INTT_READ_REQ   = 8'd77;
    localparam [7:0] S_V_INTT_READ_CAP   = 8'd78;

    localparam [7:0] S_V_ADDE2_LOAD_A    = 8'd79;
    localparam [7:0] S_V_ADDE2_LOAD_B    = 8'd80;
    localparam [7:0] S_V_ADDE2_START     = 8'd81;
    localparam [7:0] S_V_ADDE2_WAIT      = 8'd82;
    localparam [7:0] S_V_ADDE2_READ_REQ  = 8'd83;
    localparam [7:0] S_V_ADDE2_READ_CAP  = 8'd84;

    localparam [7:0] S_V_ADDMSG_LOAD_A   = 8'd85;
    localparam [7:0] S_V_ADDMSG_LOAD_B   = 8'd86;
    localparam [7:0] S_V_ADDMSG_START    = 8'd87;
    localparam [7:0] S_V_ADDMSG_WAIT     = 8'd88;
    localparam [7:0] S_V_ADDMSG_READ_REQ = 8'd89;
    localparam [7:0] S_V_ADDMSG_READ_CAP = 8'd90;

    localparam [7:0] S_COMP_U_START      = 8'd100;
    localparam [7:0] S_COMP_U_WAIT       = 8'd101;
    localparam [7:0] S_COMP_V_START      = 8'd102;
    localparam [7:0] S_COMP_V_WAIT       = 8'd103;

    localparam [7:0] S_DONE              = 8'd104;

    reg [7:0] state;

    // =============================================================
    // Input/Output byte buffers
    // =============================================================
    (* ram_style = "block" *) reg [7:0] ek_buf [0:1183];
    (* ram_style = "block" *) reg [7:0] m_buf  [0:31];
    (* ram_style = "block" *) reg [7:0] r_buf  [0:31];
    (* ram_style = "block" *) reg [7:0] ct_buf [0:1087];

    // =============================================================
    // Internal memories
    // =============================================================
    (* ram_style = "block" *) reg [15:0] t_hat_mem    [0:767];
    (* ram_style = "block" *) reg [15:0] r_hat_mem    [0:767];
    (* ram_style = "block" *) reg [15:0] e1_mem       [0:767];
    (* ram_style = "block" *) reg [15:0] e2_mem       [0:255];

    (* ram_style = "block" *) reg [15:0] a_hat_mem    [0:255];
    (* ram_style = "block" *) reg [15:0] acc_mem      [0:255];
    (* ram_style = "block" *) reg [15:0] tmp_mem      [0:255];

    (* ram_style = "block" *) reg [15:0] u_mem        [0:767];
    (* ram_style = "block" *) reg [15:0] v_mem        [0:255];
    (* ram_style = "block" *) reg [15:0] msg_poly_mem [0:255];

    reg [7:0] rho_reg [0:31];

    // Keccak/CBD local buffers
    reg [63:0] prf_buf [0:15];
    reg [63:0] prf_shift;

    // =============================================================
    // Control registers
    // =============================================================
    reg [1:0] decode_idx;

    // noise_stage: 0 -> r_hat(3 polys), 1 -> e1(3 polys), 2 -> e2(1 poly), 3 -> done
    reg [1:0] noise_stage;
    reg [1:0] noise_idx;

    reg [11:0] var_k;
    reg [3:0]  prf_word_idx;
    reg [2:0]  prf_byte_idx;

    reg [1:0] u_i;
    reg [1:0] u_j;
    reg [1:0] v_i;

    reg [7:0] coeff_idx;

    reg [1:0] comp_u_idx;
    reg [10:0] comp_base_offset;
    reg [1:0] comp_d_sel_reg;
    reg       comp_mode_v;

    integer clr_i;

    // =============================================================
    // 1) poly_frombytes for t_hat decode
    // =============================================================
    wire        fromb_start;
    wire        fromb_done;
    wire [8:0]  fromb_byte_addr;
    wire [7:0]  fromb_byte_din;
    wire        fromb_coeff_we;
    wire [6:0]  fromb_coeff_addr;
    wire [15:0] fromb_coeff_a0;
    wire [15:0] fromb_coeff_a1;

    wire [10:0] fromb_base_addr = (decode_idx == 2'd0) ? 11'd0 :
                                  (decode_idx == 2'd1) ? 11'd384 : 11'd768;
    wire [10:0] fromb_abs_addr  = fromb_base_addr + {2'b00, fromb_byte_addr};

    assign fromb_start = (state == S_DECODE_EK_START);

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
    // 2) keccak_sponge_top
    // =============================================================
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

    wire k_dout_ready = (state == S_U_PARSE_WAIT) ? parse_k_dout_ready : fsm_k_dout_ready;

    keccak_sponge_top u_keccak (
        .clk(clk),
        .rst_n(rst_n),
        .init(init_keccak),
        .hash_type(hash_type),
        .finalize(finalize_keccak),
        .din(k_din),
        .din_valid(k_din_valid),
        .din_ready(k_din_ready),
        .dout(k_dout),
        .dout_valid(k_dout_valid),
        .dout_ready(k_dout_ready)
    );

    // =============================================================
    // 3) poly_cbd_eta2_top
    // =============================================================
    reg         cbd_start;
    wire        cbd_done;
    wire [3:0]  cbd_buf_addr;
    wire [63:0] cbd_buf_dout = prf_buf[cbd_buf_addr];
    wire        cbd_ram_we;
    wire [6:0]  cbd_ram_addr;
    wire [15:0] cbd_ram_a0_din;
    wire [15:0] cbd_ram_a1_din;

    poly_cbd_eta2_top u_cbd (
        .clk(clk),
        .rst_n(rst_n),
        .start(cbd_start),
        .done(cbd_done),
        .buf_addr(cbd_buf_addr),
        .buf_dout(cbd_buf_dout),
        .ram_we(cbd_ram_we),
        .ram_addr(cbd_ram_addr),
        .ram_a0_din(cbd_ram_a0_din),
        .ram_a1_din(cbd_ram_a1_din)
    );

    // =============================================================
    // 4) ntt_top for r_hat generation
    // =============================================================
    wire        ntt_start;
    wire        ntt_done;
    wire        ntt_host_we;
    wire [7:0]  ntt_host_addr;
    wire [15:0] ntt_host_din;
    wire [15:0] ntt_host_dout;

    assign ntt_start     = (state == S_NTT_START);
    assign ntt_host_we   = (state == S_NTT_LOAD);
    assign ntt_host_addr = ((state == S_NTT_LOAD) || (state == S_NTT_READ_REQ)) ? coeff_idx : 8'd0;
    assign ntt_host_din  = tmp_mem[coeff_idx];

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
    // 5) inv_ntt_top for u/v domain conversion
    // =============================================================
    wire        intt_start;
    wire        intt_done;
    wire        intt_host_we;
    wire [7:0]  intt_host_addr;
    wire [15:0] intt_host_din;
    wire [15:0] intt_host_dout;

    assign intt_start = (state == S_U_INTT_START) || (state == S_V_INTT_START);

    assign intt_host_we = (state == S_U_INTT_LOAD) || (state == S_V_INTT_LOAD);

    assign intt_host_addr = ((state == S_U_INTT_LOAD) ||
                             (state == S_U_INTT_READ_REQ) ||
                             (state == S_V_INTT_LOAD) ||
                             (state == S_V_INTT_READ_REQ)) ? coeff_idx : 8'd0;

    assign intt_host_din = acc_mem[coeff_idx];

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
    // 6) poly_parse_inline_top for A^T
    // =============================================================
    reg         parse_start;
    wire        parse_done;
    wire        parse_ram_we_a0;
    wire        parse_ram_we_a1;
    wire [6:0]  parse_ram_addr;
    wire [15:0] parse_ram_a0_din;
    wire [15:0] parse_ram_a1_din;

    poly_parse_inline_top u_parse (
        .clk(clk),
        .rst_n(rst_n),
        .start(parse_start),
        .done(parse_done),
        .shake_dout(k_dout),
        .shake_dout_valid(k_dout_valid),
        .shake_dout_ready(parse_k_dout_ready),
        .ram_we_a0(parse_ram_we_a0),
        .ram_we_a1(parse_ram_we_a1),
        .ram_addr(parse_ram_addr),
        .ram_a0_din(parse_ram_a0_din),
        .ram_a1_din(parse_ram_a1_din)
    );

    // =============================================================
    // 7) poly_pointwise_top
    // =============================================================
    wire        pw_start;
    wire        pw_done;
    wire        pw_host_sel;
    wire        pw_host_we;
    wire [7:0]  pw_host_addr;
    wire [15:0] pw_host_din;
    wire [15:0] pw_host_dout;

    assign pw_start = (state == S_U_PW_START) || (state == S_V_PW_START);

    assign pw_host_sel = (state == S_U_PW_LOAD_B) || (state == S_V_PW_LOAD_B);

    assign pw_host_we = (state == S_U_PW_LOAD_A) || (state == S_U_PW_LOAD_B) ||
                        (state == S_V_PW_LOAD_A) || (state == S_V_PW_LOAD_B);

    assign pw_host_addr = ((state == S_U_PW_LOAD_A) || (state == S_U_PW_LOAD_B) ||
                           (state == S_U_PW_READ_REQ) ||
                           (state == S_V_PW_LOAD_A) || (state == S_V_PW_LOAD_B) ||
                           (state == S_V_PW_READ_REQ)) ? coeff_idx : 8'd0;

    assign pw_host_din = (state == S_U_PW_LOAD_A) ? a_hat_mem[coeff_idx] :
                         (state == S_U_PW_LOAD_B) ? r_hat_mem[{u_j, coeff_idx}] :
                         (state == S_V_PW_LOAD_A) ? t_hat_mem[{v_i, coeff_idx}] :
                         (state == S_V_PW_LOAD_B) ? r_hat_mem[{v_i, coeff_idx}] :
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
    // 8) poly_add_sub_top (ADD only in encrypt)
    // =============================================================
    wire        add_start;
    wire        add_done;
    wire        add_host_sel;
    wire        add_host_we;
    wire [7:0]  add_host_addr;
    wire [15:0] add_host_din;
    wire [15:0] add_host_dout;

    assign add_start = (state == S_U_ADDACC_START) ||
                       (state == S_U_ADDE1_START) ||
                       (state == S_V_ADDACC_START) ||
                       (state == S_V_ADDE2_START) ||
                       (state == S_V_ADDMSG_START);

    assign add_host_sel = (state == S_U_ADDACC_LOAD_B) ||
                          (state == S_U_ADDE1_LOAD_B) ||
                          (state == S_V_ADDACC_LOAD_B) ||
                          (state == S_V_ADDE2_LOAD_B) ||
                          (state == S_V_ADDMSG_LOAD_B);

    assign add_host_we = (state == S_U_ADDACC_LOAD_A) || (state == S_U_ADDACC_LOAD_B) ||
                         (state == S_U_ADDE1_LOAD_A)  || (state == S_U_ADDE1_LOAD_B)  ||
                         (state == S_V_ADDACC_LOAD_A) || (state == S_V_ADDACC_LOAD_B) ||
                         (state == S_V_ADDE2_LOAD_A)  || (state == S_V_ADDE2_LOAD_B)  ||
                         (state == S_V_ADDMSG_LOAD_A) || (state == S_V_ADDMSG_LOAD_B);

    assign add_host_addr = ((state == S_U_ADDACC_LOAD_A) || (state == S_U_ADDACC_LOAD_B) ||
                            (state == S_U_ADDACC_READ_REQ) ||
                            (state == S_U_ADDE1_LOAD_A) || (state == S_U_ADDE1_LOAD_B) ||
                            (state == S_U_ADDE1_READ_REQ) ||
                            (state == S_V_ADDACC_LOAD_A) || (state == S_V_ADDACC_LOAD_B) ||
                            (state == S_V_ADDACC_READ_REQ) ||
                            (state == S_V_ADDE2_LOAD_A) || (state == S_V_ADDE2_LOAD_B) ||
                            (state == S_V_ADDE2_READ_REQ) ||
                            (state == S_V_ADDMSG_LOAD_A) || (state == S_V_ADDMSG_LOAD_B) ||
                            (state == S_V_ADDMSG_READ_REQ)) ? coeff_idx : 8'd0;

    assign add_host_din = (state == S_U_ADDACC_LOAD_A) ? acc_mem[coeff_idx] :
                          (state == S_U_ADDACC_LOAD_B) ? tmp_mem[coeff_idx] :
                          (state == S_U_ADDE1_LOAD_A)  ? tmp_mem[coeff_idx] :
                          (state == S_U_ADDE1_LOAD_B)  ? e1_mem[{u_i, coeff_idx}] :
                          (state == S_V_ADDACC_LOAD_A) ? acc_mem[coeff_idx] :
                          (state == S_V_ADDACC_LOAD_B) ? tmp_mem[coeff_idx] :
                          (state == S_V_ADDE2_LOAD_A)  ? tmp_mem[coeff_idx] :
                          (state == S_V_ADDE2_LOAD_B)  ? e2_mem[coeff_idx] :
                          (state == S_V_ADDMSG_LOAD_A) ? acc_mem[coeff_idx] :
                          (state == S_V_ADDMSG_LOAD_B) ? msg_poly_mem[coeff_idx] :
                          16'd0;

    poly_add_sub_top u_add (
        .clk(clk),
        .rst_n(rst_n),
        .start(add_start),
        .is_sub(1'b0),
        .done(add_done),
        .host_sel(add_host_sel),
        .host_we(add_host_we),
        .host_addr(add_host_addr),
        .host_din(add_host_din),
        .host_dout(add_host_dout)
    );

    // =============================================================
    // 9) poly_frommsg
    // =============================================================
    wire        frommsg_start;
    wire        frommsg_done;
    wire [4:0]  frommsg_msg_addr;
    wire [7:0]  frommsg_msg_din;
    wire        frommsg_coeff_we;
    wire [6:0]  frommsg_coeff_addr;
    wire [15:0] frommsg_coeff_a0;
    wire [15:0] frommsg_coeff_a1;

    assign frommsg_start = (state == S_FROMMSG_START);

    poly_frommsg u_frommsg (
        .clk(clk),
        .rst_n(rst_n),
        .start(frommsg_start),
        .done(frommsg_done),
        .msg_addr(frommsg_msg_addr),
        .msg_din(frommsg_msg_din),
        .coeff_we(frommsg_coeff_we),
        .coeff_addr(frommsg_coeff_addr),
        .coeff_a0(frommsg_coeff_a0),
        .coeff_a1(frommsg_coeff_a1)
    );

    // =============================================================
    // 10) poly_compress
    // =============================================================
    wire        comp_start;
    wire        comp_done;
    wire [6:0]  comp_coeff_addr;
    wire [15:0] comp_coeff_a0;
    wire [15:0] comp_coeff_a1;
    wire        comp_byte_we;
    wire [8:0]  comp_byte_addr;
    wire [7:0]  comp_byte_dout;

    assign comp_start = (state == S_COMP_U_START) || (state == S_COMP_V_START);

    poly_compress u_compress (
        .clk(clk),
        .rst_n(rst_n),
        .start(comp_start),
        .d_sel(comp_d_sel_reg),
        .done(comp_done),
        .coeff_addr(comp_coeff_addr),
        .coeff_a0(comp_coeff_a0),
        .coeff_a1(comp_coeff_a1),
        .byte_we(comp_byte_we),
        .byte_addr(comp_byte_addr),
        .byte_dout(comp_byte_dout)
    );

    assign ct_we   = ((state == S_COMP_U_WAIT) || (state == S_COMP_V_WAIT)) ? comp_byte_we : 1'b0;
    assign ct_addr = comp_base_offset + {2'b00, comp_byte_addr};
    assign ct_dout = comp_byte_dout;

    // =============================================================
    // Read adapters for synchronous memories
    // =============================================================
    reg [7:0]  fromb_byte_din_r;
    reg [7:0]  frommsg_msg_din_r;
    reg [15:0] comp_coeff_a0_r;
    reg [15:0] comp_coeff_a1_r;

    assign fromb_byte_din  = fromb_byte_din_r;
    assign frommsg_msg_din = frommsg_msg_din_r;
    assign comp_coeff_a0   = comp_coeff_a0_r;
    assign comp_coeff_a1   = comp_coeff_a1_r;

    // =============================================================
    // Helpers
    // =============================================================
    wire [7:0] noise_nonce = (noise_stage == 2'd0) ? {6'd0, noise_idx} :
                             (noise_stage == 2'd1) ? ({6'd0, noise_idx} + 8'd3) :
                                                      8'd6;

    // =============================================================
    // Main FSM
    // =============================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state            <= S_IDLE;
            busy             <= 1'b0;
            done             <= 1'b0;
            out_rdata        <= 8'd0;
            out_valid        <= 1'b0;

            init_keccak      <= 1'b0;
            finalize_keccak  <= 1'b0;
            hash_type        <= 2'b00;
            k_din            <= 8'd0;
            k_din_valid      <= 1'b0;
            fsm_k_dout_ready <= 1'b0;

            cbd_start        <= 1'b0;
            parse_start      <= 1'b0;

            decode_idx       <= 2'd0;
            noise_stage      <= 2'd0;
            noise_idx        <= 2'd0;
            var_k            <= 12'd0;
            prf_word_idx     <= 4'd0;
            prf_byte_idx     <= 3'd0;
            prf_shift        <= 64'd0;

            u_i              <= 2'd0;
            u_j              <= 2'd0;
            v_i              <= 2'd0;
            coeff_idx        <= 8'd0;

            comp_u_idx       <= 2'd0;
            comp_base_offset <= 11'd0;
            comp_d_sel_reg   <= 2'b10;
            comp_mode_v      <= 1'b0;

            fromb_byte_din_r   <= 8'd0;
            frommsg_msg_din_r  <= 8'd0;
            comp_coeff_a0_r    <= 16'd0;
            comp_coeff_a1_r    <= 16'd0;

            for (clr_i = 0; clr_i < 1088; clr_i = clr_i + 1) begin
                ct_buf[clr_i] <= 8'd0;
            end
        end else begin
            done      <= 1'b0;
            out_valid <= 1'b0;

            // default pulses
            init_keccak      <= 1'b0;
            finalize_keccak  <= 1'b0;
            k_din_valid      <= 1'b0;
            fsm_k_dout_ready <= 1'b0;
            cbd_start        <= 1'b0;
            parse_start      <= 1'b0;

            // sync read adapters
            fromb_byte_din_r  <= ek_buf[fromb_abs_addr];
            frommsg_msg_din_r <= m_buf[frommsg_msg_addr];

            if (!comp_mode_v) begin
                comp_coeff_a0_r <= u_mem[{comp_u_idx, comp_coeff_addr, 1'b0}];
                comp_coeff_a1_r <= u_mem[{comp_u_idx, comp_coeff_addr, 1'b1}];
            end else begin
                comp_coeff_a0_r <= v_mem[{comp_coeff_addr, 1'b0}];
                comp_coeff_a1_r <= v_mem[{comp_coeff_addr, 1'b1}];
            end

            // preload writes when idle
            if (in_we && !busy) begin
                case (in_sel)
                    2'd0: if (in_addr < 11'd1184) ek_buf[in_addr] <= in_wdata;
                    2'd1: if (in_addr < 11'd32)   m_buf[in_addr[4:0]] <= in_wdata;
                    2'd2: if (in_addr < 11'd32)   r_buf[in_addr[4:0]] <= in_wdata;
                    default: begin end
                endcase
            end

            if (out_rd) begin
                out_valid <= 1'b1;
                if (out_addr < 11'd1088) out_rdata <= ct_buf[out_addr];
                else                      out_rdata <= 8'd0;
            end

            // datapath captures
            if (fromb_coeff_we) begin
                t_hat_mem[{decode_idx, fromb_coeff_addr, 1'b0}] <= fromb_coeff_a0;
                t_hat_mem[{decode_idx, fromb_coeff_addr, 1'b1}] <= fromb_coeff_a1;
            end

            if (parse_ram_we_a0) begin
                a_hat_mem[{parse_ram_addr, 1'b0}] <= parse_ram_a0_din;
            end
            if (parse_ram_we_a1) begin
                a_hat_mem[{parse_ram_addr, 1'b1}] <= parse_ram_a1_din;
            end

            if (frommsg_coeff_we) begin
                msg_poly_mem[{frommsg_coeff_addr, 1'b0}] <= frommsg_coeff_a0;
                msg_poly_mem[{frommsg_coeff_addr, 1'b1}] <= frommsg_coeff_a1;
            end

            if (cbd_ram_we) begin
                tmp_mem[{cbd_ram_addr, 1'b0}] <= cbd_ram_a0_din;
                tmp_mem[{cbd_ram_addr, 1'b1}] <= cbd_ram_a1_din;

                if (noise_stage == 2'd1) begin
                    e1_mem[{noise_idx, cbd_ram_addr, 1'b0}] <= cbd_ram_a0_din;
                    e1_mem[{noise_idx, cbd_ram_addr, 1'b1}] <= cbd_ram_a1_din;
                end else if (noise_stage == 2'd2) begin
                    e2_mem[{cbd_ram_addr, 1'b0}] <= cbd_ram_a0_din;
                    e2_mem[{cbd_ram_addr, 1'b1}] <= cbd_ram_a1_din;
                end
            end

            if (state == S_NTT_READ_CAP) begin
                r_hat_mem[{noise_idx, coeff_idx}] <= ntt_host_dout;
            end

            if ((state == S_U_PW_READ_CAP) || (state == S_V_PW_READ_CAP)) begin
                tmp_mem[coeff_idx] <= pw_host_dout;
            end

            if ((state == S_U_INTT_READ_CAP) || (state == S_V_INTT_READ_CAP)) begin
                tmp_mem[coeff_idx] <= intt_host_dout;
            end

            if ((state == S_U_ADDACC_READ_CAP) || (state == S_V_ADDACC_READ_CAP)) begin
                acc_mem[coeff_idx] <= add_host_dout;
            end

            if (state == S_U_ADDE1_READ_CAP) begin
                u_mem[{u_i, coeff_idx}] <= add_host_dout;
            end

            if (state == S_V_ADDE2_READ_CAP) begin
                acc_mem[coeff_idx] <= add_host_dout;
            end

            if (state == S_V_ADDMSG_READ_CAP) begin
                v_mem[coeff_idx] <= add_host_dout;
            end

            if (((state == S_COMP_U_WAIT) || (state == S_COMP_V_WAIT)) && comp_byte_we) begin
                if ((comp_base_offset + {2'b00, comp_byte_addr}) < 11'd1088) begin
                    ct_buf[comp_base_offset + {2'b00, comp_byte_addr}] <= comp_byte_dout;
                end
            end

            // FSM transitions
            case (state)
                S_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        busy             <= 1'b1;
                        decode_idx       <= 2'd0;
                        noise_stage      <= 2'd0;
                        noise_idx        <= 2'd0;
                        var_k            <= 12'd0;
                        prf_word_idx     <= 4'd0;
                        prf_byte_idx     <= 3'd0;
                        prf_shift        <= 64'd0;
                        u_i              <= 2'd0;
                        u_j              <= 2'd0;
                        v_i              <= 2'd0;
                        coeff_idx        <= 8'd0;
                        comp_u_idx       <= 2'd0;
                        comp_base_offset <= 11'd0;
                        comp_mode_v      <= 1'b0;
                        comp_d_sel_reg   <= 2'b10;

                        state <= S_DECODE_EK_START;
                    end
                end

                S_DECODE_EK_START: begin
                    state <= S_DECODE_EK_WAIT;
                end

                S_DECODE_EK_WAIT: begin
                    if (fromb_done) begin
                        if (decode_idx == 2'd2) begin
                            for (clr_i = 0; clr_i < 32; clr_i = clr_i + 1) begin
                                rho_reg[clr_i] <= ek_buf[11'd1152 + clr_i[10:0]];
                            end
                            noise_stage <= 2'd0;
                            noise_idx   <= 2'd0;
                            state       <= S_NOISE_INIT;
                        end else begin
                            decode_idx <= decode_idx + 2'd1;
                            state      <= S_DECODE_EK_START;
                        end
                    end
                end

                // -------------------------------------------------
                // Noise generation
                // -------------------------------------------------
                S_NOISE_INIT: begin
                    if (noise_stage == 2'd0 && noise_idx == 2'd3) begin
                        noise_stage <= 2'd1;
                        noise_idx   <= 2'd0;
                    end else if (noise_stage == 2'd1 && noise_idx == 2'd3) begin
                        noise_stage <= 2'd2;
                        noise_idx   <= 2'd0;
                    end else if (noise_stage == 2'd2 && noise_idx == 2'd1) begin
                        state <= S_FROMMSG_START;
                    end else begin
                        init_keccak <= 1'b1;
                        hash_type   <= 2'b01; // SHAKE256
                        var_k       <= 12'd0;
                        state       <= S_PRF_ABSORB;
                    end
                end

                S_PRF_ABSORB: begin
                    if (k_din_ready) begin
                        k_din_valid <= 1'b1;
                        if (var_k < 12'd32) begin
                            k_din <= r_buf[var_k[4:0]];
                            var_k <= var_k + 12'd1;
                        end else begin
                            k_din <= noise_nonce;
                            var_k <= 12'd0;
                            state <= S_PRF_FINAL;
                        end
                    end
                end

                S_PRF_FINAL: begin
                    finalize_keccak <= 1'b1;
                    prf_word_idx    <= 4'd0;
                    prf_byte_idx    <= 3'd0;
                    prf_shift       <= 64'd0;
                    state           <= S_PRF_WAIT;
                end

                S_PRF_WAIT: begin
                    fsm_k_dout_ready <= 1'b1;
                    if (k_dout_valid) begin
                        prf_shift <= {k_dout, prf_shift[63:8]};
                        if (prf_byte_idx == 3'd7) begin
                            prf_buf[prf_word_idx] <= {k_dout, prf_shift[63:8]};
                            prf_byte_idx <= 3'd0;
                            if (prf_word_idx == 4'd15) begin
                                fsm_k_dout_ready <= 1'b0;
                                state <= S_CBD_START;
                            end else begin
                                prf_word_idx <= prf_word_idx + 4'd1;
                            end
                        end else begin
                            prf_byte_idx <= prf_byte_idx + 3'd1;
                        end
                    end
                end

                S_CBD_START: begin
                    cbd_start <= 1'b1;
                    state     <= S_CBD_WAIT;
                end

                S_CBD_WAIT: begin
                    if (cbd_done) begin
                        if (noise_stage == 2'd0) begin
                            coeff_idx <= 8'd0;
                            state <= S_NTT_LOAD;
                        end else begin
                            noise_idx <= noise_idx + 2'd1;
                            state <= S_NOISE_INIT;
                        end
                    end
                end

                S_NTT_LOAD: begin
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
                        state <= S_NTT_READ_REQ;
                    end
                end

                S_NTT_READ_REQ: begin
                    state <= S_NTT_READ_CAP;
                end

                S_NTT_READ_CAP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        noise_idx <= noise_idx + 2'd1;
                        state <= S_NOISE_INIT;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state <= S_NTT_READ_REQ;
                    end
                end

                // -------------------------------------------------
                // encode m -> poly
                // -------------------------------------------------
                S_FROMMSG_START: begin
                    state <= S_FROMMSG_WAIT;
                end

                S_FROMMSG_WAIT: begin
                    if (frommsg_done) begin
                        u_i <= 2'd0;
                        u_j <= 2'd0;
                        state <= S_U_INIT;
                    end
                end

                // -------------------------------------------------
                // U loop
                // -------------------------------------------------
                S_U_INIT: begin
                    u_j <= 2'd0;
                    state <= S_U_XOF_INIT;
                end

                S_U_XOF_INIT: begin
                    init_keccak <= 1'b1;
                    hash_type   <= 2'b00; // SHAKE128
                    var_k       <= 12'd0;
                    state       <= S_U_XOF_ABSORB;
                end

                S_U_XOF_ABSORB: begin
                    if (k_din_ready) begin
                        k_din_valid <= 1'b1;
                        if (var_k < 12'd32) begin
                            k_din <= rho_reg[var_k[4:0]];
                            var_k <= var_k + 12'd1;
                        end else if (var_k == 12'd32) begin
                            k_din <= {6'd0, u_i};
                            var_k <= var_k + 12'd1;
                        end else begin
                            k_din <= {6'd0, u_j};
                            state <= S_U_XOF_FINAL;
                        end
                    end
                end

                S_U_XOF_FINAL: begin
                    finalize_keccak <= 1'b1;
                    state <= S_U_PARSE_START;
                end

                S_U_PARSE_START: begin
                    parse_start <= 1'b1;
                    state <= S_U_PARSE_WAIT;
                end

                S_U_PARSE_WAIT: begin
                    if (parse_done) begin
                        coeff_idx <= 8'd0;
                        state <= S_U_PW_LOAD_A;
                    end
                end

                S_U_PW_LOAD_A: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_U_PW_LOAD_B;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_U_PW_LOAD_B: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_U_PW_START;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_U_PW_START: begin
                    state <= S_U_PW_WAIT;
                end

                S_U_PW_WAIT: begin
                    if (pw_done) begin
                        coeff_idx <= 8'd0;
                        state <= S_U_PW_READ_REQ;
                    end
                end

                S_U_PW_READ_REQ: begin
                    state <= S_U_PW_READ_CAP;
                end

                S_U_PW_READ_CAP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        if (u_j == 2'd0) begin
                            state <= S_U_COPY_TMP;
                        end else begin
                            state <= S_U_ADDACC_LOAD_A;
                        end
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state <= S_U_PW_READ_REQ;
                    end
                end

                S_U_COPY_TMP: begin
                    acc_mem[coeff_idx] <= tmp_mem[coeff_idx];
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        if (u_j == 2'd2) begin
                            state <= S_U_INTT_LOAD;
                        end else begin
                            u_j <= u_j + 2'd1;
                            state <= S_U_XOF_INIT;
                        end
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_U_ADDACC_LOAD_A: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_U_ADDACC_LOAD_B;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_U_ADDACC_LOAD_B: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_U_ADDACC_START;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_U_ADDACC_START: begin
                    state <= S_U_ADDACC_WAIT;
                end

                S_U_ADDACC_WAIT: begin
                    if (add_done) begin
                        coeff_idx <= 8'd0;
                        state <= S_U_ADDACC_READ_REQ;
                    end
                end

                S_U_ADDACC_READ_REQ: begin
                    state <= S_U_ADDACC_READ_CAP;
                end

                S_U_ADDACC_READ_CAP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        if (u_j == 2'd2) begin
                            state <= S_U_INTT_LOAD;
                        end else begin
                            u_j <= u_j + 2'd1;
                            state <= S_U_XOF_INIT;
                        end
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state <= S_U_ADDACC_READ_REQ;
                    end
                end

                S_U_INTT_LOAD: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_U_INTT_START;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_U_INTT_START: begin
                    state <= S_U_INTT_WAIT;
                end

                S_U_INTT_WAIT: begin
                    if (intt_done) begin
                        coeff_idx <= 8'd0;
                        state <= S_U_INTT_READ_REQ;
                    end
                end

                S_U_INTT_READ_REQ: begin
                    state <= S_U_INTT_READ_CAP;
                end

                S_U_INTT_READ_CAP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_U_ADDE1_LOAD_A;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state <= S_U_INTT_READ_REQ;
                    end
                end

                S_U_ADDE1_LOAD_A: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_U_ADDE1_LOAD_B;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_U_ADDE1_LOAD_B: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_U_ADDE1_START;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_U_ADDE1_START: begin
                    state <= S_U_ADDE1_WAIT;
                end

                S_U_ADDE1_WAIT: begin
                    if (add_done) begin
                        coeff_idx <= 8'd0;
                        state <= S_U_ADDE1_READ_REQ;
                    end
                end

                S_U_ADDE1_READ_REQ: begin
                    state <= S_U_ADDE1_READ_CAP;
                end

                S_U_ADDE1_READ_CAP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        if (u_i == 2'd2) begin
                            v_i <= 2'd0;
                            state <= S_V_INIT;
                        end else begin
                            u_i <= u_i + 2'd1;
                            state <= S_U_INIT;
                        end
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state <= S_U_ADDE1_READ_REQ;
                    end
                end

                // -------------------------------------------------
                // V loop
                // -------------------------------------------------
                S_V_INIT: begin
                    coeff_idx <= 8'd0;
                    state <= S_V_PW_LOAD_A;
                end

                S_V_PW_LOAD_A: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_PW_LOAD_B;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_V_PW_LOAD_B: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_PW_START;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_V_PW_START: begin
                    state <= S_V_PW_WAIT;
                end

                S_V_PW_WAIT: begin
                    if (pw_done) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_PW_READ_REQ;
                    end
                end

                S_V_PW_READ_REQ: begin
                    state <= S_V_PW_READ_CAP;
                end

                S_V_PW_READ_CAP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        if (v_i == 2'd0) begin
                            state <= S_V_COPY_TMP;
                        end else begin
                            state <= S_V_ADDACC_LOAD_A;
                        end
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state <= S_V_PW_READ_REQ;
                    end
                end

                S_V_COPY_TMP: begin
                    acc_mem[coeff_idx] <= tmp_mem[coeff_idx];
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        v_i <= 2'd1;
                        state <= S_V_PW_LOAD_A;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_V_ADDACC_LOAD_A: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_ADDACC_LOAD_B;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_V_ADDACC_LOAD_B: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_ADDACC_START;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_V_ADDACC_START: begin
                    state <= S_V_ADDACC_WAIT;
                end

                S_V_ADDACC_WAIT: begin
                    if (add_done) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_ADDACC_READ_REQ;
                    end
                end

                S_V_ADDACC_READ_REQ: begin
                    state <= S_V_ADDACC_READ_CAP;
                end

                S_V_ADDACC_READ_CAP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        if (v_i == 2'd2) begin
                            state <= S_V_INTT_LOAD;
                        end else begin
                            v_i <= v_i + 2'd1;
                            state <= S_V_PW_LOAD_A;
                        end
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state <= S_V_ADDACC_READ_REQ;
                    end
                end

                S_V_INTT_LOAD: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_INTT_START;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_V_INTT_START: begin
                    state <= S_V_INTT_WAIT;
                end

                S_V_INTT_WAIT: begin
                    if (intt_done) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_INTT_READ_REQ;
                    end
                end

                S_V_INTT_READ_REQ: begin
                    state <= S_V_INTT_READ_CAP;
                end

                S_V_INTT_READ_CAP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_ADDE2_LOAD_A;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state <= S_V_INTT_READ_REQ;
                    end
                end

                S_V_ADDE2_LOAD_A: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_ADDE2_LOAD_B;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_V_ADDE2_LOAD_B: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_ADDE2_START;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_V_ADDE2_START: begin
                    state <= S_V_ADDE2_WAIT;
                end

                S_V_ADDE2_WAIT: begin
                    if (add_done) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_ADDE2_READ_REQ;
                    end
                end

                S_V_ADDE2_READ_REQ: begin
                    state <= S_V_ADDE2_READ_CAP;
                end

                S_V_ADDE2_READ_CAP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_ADDMSG_LOAD_A;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state <= S_V_ADDE2_READ_REQ;
                    end
                end

                S_V_ADDMSG_LOAD_A: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_ADDMSG_LOAD_B;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_V_ADDMSG_LOAD_B: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_ADDMSG_START;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_V_ADDMSG_START: begin
                    state <= S_V_ADDMSG_WAIT;
                end

                S_V_ADDMSG_WAIT: begin
                    if (add_done) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_ADDMSG_READ_REQ;
                    end
                end

                S_V_ADDMSG_READ_REQ: begin
                    state <= S_V_ADDMSG_READ_CAP;
                end

                S_V_ADDMSG_READ_CAP: begin
                    if (coeff_idx == 8'd255) begin
                        comp_u_idx       <= 2'd0;
                        comp_base_offset <= 11'd0;
                        comp_d_sel_reg   <= 2'b10; // d=10
                        comp_mode_v      <= 1'b0;
                        state <= S_COMP_U_START;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state <= S_V_ADDMSG_READ_REQ;
                    end
                end

                // -------------------------------------------------
                // Compression
                // -------------------------------------------------
                S_COMP_U_START: begin
                    state <= S_COMP_U_WAIT;
                end

                S_COMP_U_WAIT: begin
                    if (comp_done) begin
                        if (comp_u_idx == 2'd2) begin
                            comp_mode_v      <= 1'b1;
                            comp_d_sel_reg   <= 2'b01; // d=4
                            comp_base_offset <= 11'd960;
                            state            <= S_COMP_V_START;
                        end else begin
                            comp_u_idx       <= comp_u_idx + 2'd1;
                            comp_base_offset <= comp_base_offset + 11'd320;
                            state            <= S_COMP_U_START;
                        end
                    end
                end

                S_COMP_V_START: begin
                    state <= S_COMP_V_WAIT;
                end

                S_COMP_V_WAIT: begin
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
