`timescale 1ns / 1ps

module kpke_encrypt #(
    parameter HAS_INTERNAL_KECCAK = 1
) (
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
    output wire [7:0]   ct_dout,

    // External keccak interface, used only when HAS_INTERNAL_KECCAK == 0.
    output wire         ext_k_init,
    output wire [1:0]   ext_k_hash_type,
    output wire         ext_k_finalize,
    output wire [7:0]   ext_k_din,
    output wire         ext_k_din_valid,
    input  wire         ext_k_din_ready,
    input  wire [7:0]   ext_k_dout,
    input  wire         ext_k_dout_valid,
    output wire         ext_k_dout_ready
);

    // =============================================================
    // FSM states
    // =============================================================
    localparam [6:0] S_IDLE                 = 7'd0;

    localparam [6:0] S_DECODE_EK_START      = 7'd1;
    localparam [6:0] S_DECODE_EK_WAIT       = 7'd2;

    localparam [6:0] S_NOISE_INIT           = 7'd3;
    localparam [6:0] S_PRF_ABSORB           = 7'd4;
    localparam [6:0] S_PRF_FINAL            = 7'd5;
    localparam [6:0] S_PRF_WAIT             = 7'd6;
    localparam [6:0] S_CBD_START            = 7'd7;
    localparam [6:0] S_CBD_WAIT             = 7'd8;
    localparam [6:0] S_NTT_LOAD_PREF        = 7'd9;
    localparam [6:0] S_NTT_LOAD_LOOP        = 7'd10;
    localparam [6:0] S_NTT_START            = 7'd11;
    localparam [6:0] S_NTT_WAIT             = 7'd12;
    localparam [6:0] S_NTT_READ_REQ         = 7'd13;
    localparam [6:0] S_NTT_READ_CAP         = 7'd14;

    localparam [6:0] S_FROMMSG_START        = 7'd15;
    localparam [6:0] S_FROMMSG_WAIT         = 7'd16;

    localparam [6:0] S_U_INIT               = 7'd17;
    localparam [6:0] S_U_XOF_INIT           = 7'd18;
    localparam [6:0] S_U_XOF_ABSORB         = 7'd19;
    localparam [6:0] S_U_XOF_FINAL          = 7'd20;
    localparam [6:0] S_U_PARSE_START        = 7'd21;
    localparam [6:0] S_U_PARSE_WAIT         = 7'd22;

    localparam [6:0] S_U_PW_LOAD_A_PREF     = 7'd23;
    localparam [6:0] S_U_PW_LOAD_A_LOOP     = 7'd24;
    localparam [6:0] S_U_PW_LOAD_B_PREF     = 7'd25;
    localparam [6:0] S_U_PW_LOAD_B_LOOP     = 7'd26;
    localparam [6:0] S_U_PW_START           = 7'd27;
    localparam [6:0] S_U_PW_WAIT            = 7'd28;
    localparam [6:0] S_U_PW_READ_REQ        = 7'd29;
    localparam [6:0] S_U_PW_READ_CAP        = 7'd30;

    localparam [6:0] S_U_ACC_LOAD_A_PREF    = 7'd31;
    localparam [6:0] S_U_ACC_LOAD_A_LOOP    = 7'd32;
    localparam [6:0] S_U_ACC_LOAD_B_PREF    = 7'd33;
    localparam [6:0] S_U_ACC_LOAD_B_LOOP    = 7'd34;
    localparam [6:0] S_U_ACC_START          = 7'd35;
    localparam [6:0] S_U_ACC_WAIT           = 7'd36;
    localparam [6:0] S_U_ACC_READ_REQ       = 7'd37;
    localparam [6:0] S_U_ACC_READ_CAP       = 7'd38;

    localparam [6:0] S_U_INTT_LOAD_PREF     = 7'd39;
    localparam [6:0] S_U_INTT_LOAD_LOOP     = 7'd40;
    localparam [6:0] S_U_INTT_START         = 7'd41;
    localparam [6:0] S_U_INTT_WAIT          = 7'd42;
    localparam [6:0] S_U_INTT_READ_REQ      = 7'd43;
    localparam [6:0] S_U_INTT_READ_CAP      = 7'd44;

    localparam [6:0] S_U_ADDE1_LOAD_A_PREF  = 7'd45;
    localparam [6:0] S_U_ADDE1_LOAD_A_LOOP  = 7'd46;
    localparam [6:0] S_U_ADDE1_LOAD_B_PREF  = 7'd47;
    localparam [6:0] S_U_ADDE1_LOAD_B_LOOP  = 7'd48;
    localparam [6:0] S_U_ADDE1_START        = 7'd49;
    localparam [6:0] S_U_ADDE1_WAIT         = 7'd50;
    localparam [6:0] S_U_ADDE1_READ_REQ     = 7'd51;
    localparam [6:0] S_U_ADDE1_READ_CAP     = 7'd52;

    localparam [6:0] S_V_INIT               = 7'd53;
    localparam [6:0] S_V_PW_LOAD_A_PREF     = 7'd54;
    localparam [6:0] S_V_PW_LOAD_A_LOOP     = 7'd55;
    localparam [6:0] S_V_PW_LOAD_B_PREF     = 7'd56;
    localparam [6:0] S_V_PW_LOAD_B_LOOP     = 7'd57;
    localparam [6:0] S_V_PW_START           = 7'd58;
    localparam [6:0] S_V_PW_WAIT            = 7'd59;
    localparam [6:0] S_V_PW_READ_REQ        = 7'd60;
    localparam [6:0] S_V_PW_READ_CAP        = 7'd61;

    localparam [6:0] S_V_ACC_LOAD_A_PREF    = 7'd62;
    localparam [6:0] S_V_ACC_LOAD_A_LOOP    = 7'd63;
    localparam [6:0] S_V_ACC_LOAD_B_PREF    = 7'd64;
    localparam [6:0] S_V_ACC_LOAD_B_LOOP    = 7'd65;
    localparam [6:0] S_V_ACC_START          = 7'd66;
    localparam [6:0] S_V_ACC_WAIT           = 7'd67;
    localparam [6:0] S_V_ACC_READ_REQ       = 7'd68;
    localparam [6:0] S_V_ACC_READ_CAP       = 7'd69;

    localparam [6:0] S_V_INTT_LOAD_PREF     = 7'd70;
    localparam [6:0] S_V_INTT_LOAD_LOOP     = 7'd71;
    localparam [6:0] S_V_INTT_START         = 7'd72;
    localparam [6:0] S_V_INTT_WAIT          = 7'd73;
    localparam [6:0] S_V_INTT_READ_REQ      = 7'd74;
    localparam [6:0] S_V_INTT_READ_CAP      = 7'd75;

    localparam [6:0] S_V_ADDE2_LOAD_A_PREF  = 7'd76;
    localparam [6:0] S_V_ADDE2_LOAD_A_LOOP  = 7'd77;
    localparam [6:0] S_V_ADDE2_LOAD_B_PREF  = 7'd78;
    localparam [6:0] S_V_ADDE2_LOAD_B_LOOP  = 7'd79;
    localparam [6:0] S_V_ADDE2_START        = 7'd80;
    localparam [6:0] S_V_ADDE2_WAIT         = 7'd81;
    localparam [6:0] S_V_ADDE2_READ_REQ     = 7'd82;
    localparam [6:0] S_V_ADDE2_READ_CAP     = 7'd83;

    localparam [6:0] S_V_ADDMSG_LOAD_A_PREF = 7'd84;
    localparam [6:0] S_V_ADDMSG_LOAD_A_LOOP = 7'd85;
    localparam [6:0] S_V_ADDMSG_LOAD_B_PREF = 7'd86;
    localparam [6:0] S_V_ADDMSG_LOAD_B_LOOP = 7'd87;
    localparam [6:0] S_V_ADDMSG_START       = 7'd88;
    localparam [6:0] S_V_ADDMSG_WAIT        = 7'd89;
    localparam [6:0] S_V_ADDMSG_READ_REQ    = 7'd90;
    localparam [6:0] S_V_ADDMSG_READ_CAP    = 7'd91;

    localparam [6:0] S_COMP_U_PREF          = 7'd92;
    localparam [6:0] S_COMP_U_START         = 7'd93;
    localparam [6:0] S_COMP_U_WAIT          = 7'd94;
    localparam [6:0] S_COMP_V_PREF          = 7'd95;
    localparam [6:0] S_COMP_V_START         = 7'd96;
    localparam [6:0] S_COMP_V_WAIT          = 7'd97;

    localparam [6:0] S_DONE                 = 7'd98;

    reg [6:0] state;

    // =============================================================
    // Input/output byte buffers
    // =============================================================
    (* ram_style = "block" *) reg [7:0] ek_buf [0:1183];
    reg [7:0] m_buf [0:31];
    reg [7:0] r_buf [0:31];
    reg         ct_rd_en;
    reg [10:0]  ct_rd_addr;
    wire [7:0]  ct_rd_data;
    reg         ct_rd_pending;
    reg         ct_rd_pending_d1;

    // =============================================================
    // Internal memories (Phase-2 banked style)
    // =============================================================
    // t_hat/e1/u: 3 polys * 128 pairs
    (* ram_style = "block" *) reg [15:0] t_hat_mem0 [0:383];
    (* ram_style = "block" *) reg [15:0] t_hat_mem1 [0:383];
    (* ram_style = "block" *) reg [15:0] e1_mem0    [0:383];
    (* ram_style = "block" *) reg [15:0] e1_mem1    [0:383];
    (* ram_style = "block" *) reg [15:0] u_mem0     [0:383];
    (* ram_style = "block" *) reg [15:0] u_mem1     [0:383];

    // v/e2/a_hat/msg: 1 poly * 128 pairs
    (* ram_style = "block" *) reg [15:0] e2_mem0      [0:127];
    (* ram_style = "block" *) reg [15:0] e2_mem1      [0:127];
    (* ram_style = "block" *) reg [15:0] a_hat_mem0   [0:127];
    (* ram_style = "block" *) reg [15:0] a_hat_mem1   [0:127];
    (* ram_style = "block" *) reg [15:0] v_mem0       [0:127];
    (* ram_style = "block" *) reg [15:0] v_mem1       [0:127];
    (* ram_style = "block" *) reg [15:0] msg_poly_mem0[0:127];
    (* ram_style = "block" *) reg [15:0] msg_poly_mem1[0:127];

    // Single-lane memories
    (* ram_style = "block" *) reg [15:0] r_hat_mem [0:767];
    (* ram_style = "block" *) reg [15:0] acc_mem   [0:255];
    (* ram_style = "block" *) reg [15:0] tmp_mem   [0:255];

    // =============================================================
    // Internal registers
    // =============================================================
    reg [7:0] rho_reg [0:31];
    reg [63:0] prf_buf [0:15];
    reg [63:0] prf_shift;

    reg [1:0] decode_idx;
    reg [1:0] noise_stage; // 0:r, 1:e1, 2:e2
    reg [1:0] noise_idx;

    reg [11:0] var_k;
    reg [3:0]  prf_word_idx;
    reg [2:0]  prf_byte_idx;

    reg [1:0] u_i;
    reg [1:0] u_j;
    reg [1:0] v_i;
    reg [7:0] coeff_idx;
    wire [7:0] coeff_idx_next;

    reg [1:0] comp_u_idx;
    reg [10:0] comp_base_offset;
    reg [1:0] comp_d_sel_reg;
    reg       comp_mode_v;


    // =============================================================
    // Synchronous read adapters and memory read registers
    // =============================================================
    reg [7:0] fromb_byte_din_r;

    reg [15:0] t_hat_rd_a0, t_hat_rd_a1;
    reg [15:0] e1_rd_a0, e1_rd_a1;
    reg [15:0] e2_rd_a0, e2_rd_a1;
    reg [15:0] a_hat_rd_a0, a_hat_rd_a1;
    reg [15:0] u_rd_a0, u_rd_a1;
    reg [15:0] v_rd_a0, v_rd_a1;
    reg [15:0] msg_poly_rd_a0, msg_poly_rd_a1;

    reg [15:0] r_hat_rdata;
    reg [15:0] acc_rdata;
    reg [15:0] tmp_rdata;

    wire [8:0] t_hat_rpair_addr;
    wire [8:0] e1_rpair_addr;
    wire [6:0] e2_rpair_addr;
    wire [6:0] a_hat_rpair_addr;
    wire [8:0] u_rpair_addr;
    wire [6:0] v_rpair_addr;
    wire [6:0] msg_poly_rpair_addr;

    wire [9:0] r_hat_raddr;
    wire [7:0] acc_raddr;
    wire [7:0] tmp_raddr;

    wire [15:0] t_hat_load_din;
    wire [15:0] e1_load_din;
    wire [15:0] e2_load_din;
    wire [15:0] a_hat_load_din;
    wire [15:0] u_load_din;
    wire [15:0] v_load_din;
    wire [15:0] msg_poly_load_din;

    // poly_compress interface (declared early to avoid use-before-declaration warnings)
    wire        comp_start;
    wire        comp_done;
    wire [6:0]  comp_coeff_addr;
    wire [15:0] comp_coeff_a0;
    wire [15:0] comp_coeff_a1;
    wire        comp_byte_we;
    wire [8:0]  comp_byte_addr;
    wire [7:0]  comp_byte_dout;

    assign coeff_idx_next = (coeff_idx == 8'd255) ? 8'd255 : (coeff_idx + 8'd1);

    assign t_hat_rpair_addr = (state == S_V_PW_LOAD_A_PREF) ? {v_i, 7'd0} :
                              (state == S_V_PW_LOAD_A_LOOP) ? {v_i, coeff_idx_next[7:1]} :
                              9'd0;
    assign e1_rpair_addr = (state == S_U_ADDE1_LOAD_B_PREF) ? {u_i, 7'd0} :
                           (state == S_U_ADDE1_LOAD_B_LOOP) ? {u_i, coeff_idx_next[7:1]} :
                           9'd0;
    assign e2_rpair_addr = (state == S_V_ADDE2_LOAD_B_PREF) ? 7'd0 :
                           (state == S_V_ADDE2_LOAD_B_LOOP) ? coeff_idx_next[7:1] :
                           7'd0;
    assign a_hat_rpair_addr = (state == S_U_PW_LOAD_A_PREF) ? 7'd0 :
                              (state == S_U_PW_LOAD_A_LOOP) ? coeff_idx_next[7:1] :
                              7'd0;
    assign u_rpair_addr = (state == S_COMP_U_PREF) ? {comp_u_idx, 7'd0} :
                          ((state == S_COMP_U_START) || (state == S_COMP_U_WAIT)) ? {comp_u_idx, comp_coeff_addr} :
                          9'd0;
    assign v_rpair_addr = (state == S_COMP_V_PREF) ? 7'd0 :
                          ((state == S_COMP_V_START) || (state == S_COMP_V_WAIT)) ? comp_coeff_addr :
                          7'd0;
    assign msg_poly_rpair_addr = (state == S_V_ADDMSG_LOAD_B_PREF) ? 7'd0 :
                                 (state == S_V_ADDMSG_LOAD_B_LOOP) ? coeff_idx_next[7:1] :
                                 7'd0;

    assign r_hat_raddr = (state == S_U_PW_LOAD_B_PREF) ? {u_j, 8'd0} :
                         (state == S_U_PW_LOAD_B_LOOP) ? {u_j, coeff_idx_next} :
                         (state == S_V_PW_LOAD_B_PREF) ? {v_i, 8'd0} :
                         (state == S_V_PW_LOAD_B_LOOP) ? {v_i, coeff_idx_next} :
                         10'd0;

    assign acc_raddr = ((state == S_U_ACC_LOAD_A_PREF) ||
                        (state == S_U_INTT_LOAD_PREF) ||
                        (state == S_V_ACC_LOAD_A_PREF) ||
                        (state == S_V_INTT_LOAD_PREF) ||
                        (state == S_V_ADDMSG_LOAD_A_PREF)) ? 8'd0 :
                       ((state == S_U_ACC_LOAD_A_LOOP) ||
                        (state == S_U_INTT_LOAD_LOOP) ||
                        (state == S_V_ACC_LOAD_A_LOOP) ||
                        (state == S_V_INTT_LOAD_LOOP) ||
                        (state == S_V_ADDMSG_LOAD_A_LOOP)) ? coeff_idx_next :
                       8'd0;

    assign tmp_raddr = ((state == S_NTT_LOAD_PREF) ||
                        (state == S_U_ACC_LOAD_B_PREF) ||
                        (state == S_U_ADDE1_LOAD_A_PREF) ||
                        (state == S_V_ACC_LOAD_B_PREF) ||
                        (state == S_V_ADDE2_LOAD_A_PREF)) ? 8'd0 :
                       ((state == S_NTT_LOAD_LOOP) ||
                        (state == S_U_ACC_LOAD_B_LOOP) ||
                        (state == S_U_ADDE1_LOAD_A_LOOP) ||
                        (state == S_V_ACC_LOAD_B_LOOP) ||
                        (state == S_V_ADDE2_LOAD_A_LOOP)) ? coeff_idx_next :
                       8'd0;

    assign t_hat_load_din   = coeff_idx[0] ? t_hat_rd_a1   : t_hat_rd_a0;
    assign e1_load_din      = coeff_idx[0] ? e1_rd_a1      : e1_rd_a0;
    assign e2_load_din      = coeff_idx[0] ? e2_rd_a1      : e2_rd_a0;
    assign a_hat_load_din   = coeff_idx[0] ? a_hat_rd_a1   : a_hat_rd_a0;
    assign u_load_din       = coeff_idx[0] ? u_rd_a1       : u_rd_a0;
    assign v_load_din       = coeff_idx[0] ? v_rd_a1       : v_rd_a0;
    assign msg_poly_load_din= coeff_idx[0] ? msg_poly_rd_a1: msg_poly_rd_a0;

    // =============================================================
    // 1) poly_frombytes
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
    assign fromb_byte_din = fromb_byte_din_r;

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
    // 2) keccak
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

    generate
        if (HAS_INTERNAL_KECCAK) begin : gen_int_keccak
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

            assign ext_k_init       = 1'b0;
            assign ext_k_hash_type  = 2'b00;
            assign ext_k_finalize   = 1'b0;
            assign ext_k_din        = 8'd0;
            assign ext_k_din_valid  = 1'b0;
            assign ext_k_dout_ready = 1'b0;
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
        end
    endgenerate

    // =============================================================
    // 3) poly_cbd_eta2_top
    // =============================================================
    reg         cbd_start;
    wire        cbd_done;
    wire [3:0]  cbd_buf_addr;
    wire [63:0] cbd_buf_dout;
    wire        cbd_ram_we;
    wire [6:0]  cbd_ram_addr;
    wire [15:0] cbd_ram_a0_din;
    wire [15:0] cbd_ram_a1_din;

    assign cbd_buf_dout = prf_buf[cbd_buf_addr];

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
    // 4) ntt_top
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
    assign ntt_host_din  = tmp_rdata;

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
    // 5) inv_ntt_top
    // =============================================================
    wire        intt_start;
    wire        intt_done;
    wire        intt_host_we;
    wire [7:0]  intt_host_addr;
    wire [15:0] intt_host_din;
    wire [15:0] intt_host_dout;

    assign intt_start = (state == S_U_INTT_START) || (state == S_V_INTT_START);
    assign intt_host_we = (state == S_U_INTT_LOAD_LOOP) || (state == S_V_INTT_LOAD_LOOP);
    assign intt_host_addr = ((state == S_U_INTT_LOAD_LOOP) ||
                             (state == S_U_INTT_READ_REQ) ||
                             (state == S_V_INTT_LOAD_LOOP) ||
                             (state == S_V_INTT_READ_REQ)) ? coeff_idx : 8'd0;
    assign intt_host_din = acc_rdata;

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
    // 6) poly_parse_inline_top
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
    assign pw_host_sel = (state == S_U_PW_LOAD_B_LOOP) || (state == S_V_PW_LOAD_B_LOOP);
    assign pw_host_we = (state == S_U_PW_LOAD_A_LOOP) || (state == S_U_PW_LOAD_B_LOOP) ||
                        (state == S_V_PW_LOAD_A_LOOP) || (state == S_V_PW_LOAD_B_LOOP);
    assign pw_host_addr = ((state == S_U_PW_LOAD_A_LOOP) || (state == S_U_PW_LOAD_B_LOOP) ||
                           (state == S_U_PW_READ_REQ) ||
                           (state == S_V_PW_LOAD_A_LOOP) || (state == S_V_PW_LOAD_B_LOOP) ||
                           (state == S_V_PW_READ_REQ)) ? coeff_idx : 8'd0;
    assign pw_host_din = (state == S_U_PW_LOAD_A_LOOP) ? a_hat_load_din :
                         (state == S_U_PW_LOAD_B_LOOP) ? r_hat_rdata :
                         (state == S_V_PW_LOAD_A_LOOP) ? t_hat_load_din :
                         (state == S_V_PW_LOAD_B_LOOP) ? r_hat_rdata :
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
    // 8) poly_add_sub_top (ADD mode)
    // =============================================================
    wire        add_start;
    wire        add_done;
    wire        add_host_sel;
    wire        add_host_we;
    wire [7:0]  add_host_addr;
    wire [15:0] add_host_din;
    wire [15:0] add_host_dout;

    assign add_start = (state == S_U_ACC_START)  || (state == S_U_ADDE1_START) ||
                       (state == S_V_ACC_START)  || (state == S_V_ADDE2_START) ||
                       (state == S_V_ADDMSG_START);
    assign add_host_sel = (state == S_U_ACC_LOAD_B_LOOP)  || (state == S_U_ADDE1_LOAD_B_LOOP) ||
                          (state == S_V_ACC_LOAD_B_LOOP)  || (state == S_V_ADDE2_LOAD_B_LOOP) ||
                          (state == S_V_ADDMSG_LOAD_B_LOOP);
    assign add_host_we = (state == S_U_ACC_LOAD_A_LOOP)  || (state == S_U_ACC_LOAD_B_LOOP) ||
                         (state == S_U_ADDE1_LOAD_A_LOOP)|| (state == S_U_ADDE1_LOAD_B_LOOP) ||
                         (state == S_V_ACC_LOAD_A_LOOP)  || (state == S_V_ACC_LOAD_B_LOOP) ||
                         (state == S_V_ADDE2_LOAD_A_LOOP)|| (state == S_V_ADDE2_LOAD_B_LOOP) ||
                         (state == S_V_ADDMSG_LOAD_A_LOOP)|| (state == S_V_ADDMSG_LOAD_B_LOOP);

    assign add_host_addr = ((state == S_U_ACC_LOAD_A_LOOP)  || (state == S_U_ACC_LOAD_B_LOOP) ||
                            (state == S_U_ACC_READ_REQ)      ||
                            (state == S_U_ADDE1_LOAD_A_LOOP) || (state == S_U_ADDE1_LOAD_B_LOOP) ||
                            (state == S_U_ADDE1_READ_REQ)    ||
                            (state == S_V_ACC_LOAD_A_LOOP)   || (state == S_V_ACC_LOAD_B_LOOP) ||
                            (state == S_V_ACC_READ_REQ)      ||
                            (state == S_V_ADDE2_LOAD_A_LOOP) || (state == S_V_ADDE2_LOAD_B_LOOP) ||
                            (state == S_V_ADDE2_READ_REQ)    ||
                            (state == S_V_ADDMSG_LOAD_A_LOOP)|| (state == S_V_ADDMSG_LOAD_B_LOOP) ||
                            (state == S_V_ADDMSG_READ_REQ)) ? coeff_idx : 8'd0;

    assign add_host_din = (state == S_U_ACC_LOAD_A_LOOP)    ? acc_rdata :
                          (state == S_U_ACC_LOAD_B_LOOP)    ? tmp_rdata :
                          (state == S_U_ADDE1_LOAD_A_LOOP)  ? tmp_rdata :
                          (state == S_U_ADDE1_LOAD_B_LOOP)  ? e1_load_din :
                          (state == S_V_ACC_LOAD_A_LOOP)    ? acc_rdata :
                          (state == S_V_ACC_LOAD_B_LOOP)    ? tmp_rdata :
                          (state == S_V_ADDE2_LOAD_A_LOOP)  ? tmp_rdata :
                          (state == S_V_ADDE2_LOAD_B_LOOP)  ? e2_load_din :
                          (state == S_V_ADDMSG_LOAD_A_LOOP) ? acc_rdata :
                          (state == S_V_ADDMSG_LOAD_B_LOOP) ? msg_poly_load_din :
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

    assign frommsg_start   = (state == S_FROMMSG_START);
    assign frommsg_msg_din = m_buf[frommsg_msg_addr];

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
    assign comp_start = (state == S_COMP_U_START) || (state == S_COMP_V_START);
    assign comp_coeff_a0 = comp_mode_v ? v_rd_a0 : u_rd_a0;
    assign comp_coeff_a1 = comp_mode_v ? v_rd_a1 : u_rd_a1;

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

    xpm_ram_sdp_byte #(
        .ADDR_WIDTH(11),
        .DEPTH(2048),
        .READ_LATENCY(1)
    ) u_ct_buf_ram (
        .clk    (clk),
        .wr_en  ((((state == S_COMP_U_WAIT) || (state == S_COMP_V_WAIT)) && comp_byte_we &&
                  ((comp_base_offset + {2'b00, comp_byte_addr}) < 11'd1088))),
        .wr_addr(comp_base_offset + {2'b00, comp_byte_addr}),
        .wr_data(comp_byte_dout),
        .rd_en  (ct_rd_en),
        .rd_addr(ct_rd_addr),
        .rd_data(ct_rd_data)
    );

    // =============================================================
    // Byte buffer process
    // =============================================================
    always @(posedge clk) begin
        if (in_we && !busy) begin
            case (in_sel)
                2'd0: begin
                    if (in_addr < 11'd1184) begin
                        ek_buf[in_addr] <= in_wdata;
                        // Capture rho slice (ek bytes 1152..1183) on-the-fly so
                        // we don't later need a 32-way parallel read of ek_buf,
                        // which would kill BRAM inference on the whole array.
                        if (in_addr >= 11'd1152) begin
                            rho_reg[in_addr[4:0]] <= in_wdata;
                        end
                    end
                end
                2'd1: begin
                    if (in_addr < 11'd32) begin
                        m_buf[in_addr[4:0]] <= in_wdata;
                    end
                end
                2'd2: begin
                    if (in_addr < 11'd32) begin
                        r_buf[in_addr[4:0]] <= in_wdata;
                    end
                end
                default: begin end
            endcase
        end

        fromb_byte_din_r  <= ek_buf[fromb_abs_addr];

    end

    // =============================================================
    // Internal memory processes (Phase-2 separated always blocks)
    // =============================================================
    always @(posedge clk) begin
        if (!rst_n) begin
            t_hat_rd_a0 <= 16'd0;
            t_hat_rd_a1 <= 16'd0;
        end else begin
            t_hat_rd_a0 <= t_hat_mem0[t_hat_rpair_addr];
            t_hat_rd_a1 <= t_hat_mem1[t_hat_rpair_addr];
            if (fromb_coeff_we) begin
                t_hat_mem0[{decode_idx, fromb_coeff_addr}] <= fromb_coeff_a0;
                t_hat_mem1[{decode_idx, fromb_coeff_addr}] <= fromb_coeff_a1;
            end
        end
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            e1_rd_a0 <= 16'd0;
            e1_rd_a1 <= 16'd0;
        end else begin
            e1_rd_a0 <= e1_mem0[e1_rpair_addr];
            e1_rd_a1 <= e1_mem1[e1_rpair_addr];
            if (cbd_ram_we && (noise_stage == 2'd1)) begin
                e1_mem0[{noise_idx, cbd_ram_addr}] <= cbd_ram_a0_din;
                e1_mem1[{noise_idx, cbd_ram_addr}] <= cbd_ram_a1_din;
            end
        end
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            e2_rd_a0 <= 16'd0;
            e2_rd_a1 <= 16'd0;
        end else begin
            e2_rd_a0 <= e2_mem0[e2_rpair_addr];
            e2_rd_a1 <= e2_mem1[e2_rpair_addr];
            if (cbd_ram_we && (noise_stage == 2'd2)) begin
                e2_mem0[cbd_ram_addr] <= cbd_ram_a0_din;
                e2_mem1[cbd_ram_addr] <= cbd_ram_a1_din;
            end
        end
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            a_hat_rd_a0 <= 16'd0;
            a_hat_rd_a1 <= 16'd0;
        end else begin
            a_hat_rd_a0 <= a_hat_mem0[a_hat_rpair_addr];
            a_hat_rd_a1 <= a_hat_mem1[a_hat_rpair_addr];
            if (parse_ram_we_a0) begin
                a_hat_mem0[parse_ram_addr] <= parse_ram_a0_din;
            end
            if (parse_ram_we_a1) begin
                a_hat_mem1[parse_ram_addr] <= parse_ram_a1_din;
            end
        end
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            u_rd_a0 <= 16'd0;
            u_rd_a1 <= 16'd0;
        end else begin
            u_rd_a0 <= u_mem0[u_rpair_addr];
            u_rd_a1 <= u_mem1[u_rpair_addr];
            if (state == S_U_ADDE1_READ_CAP) begin
                if (coeff_idx[0]) begin
                    u_mem1[{u_i, coeff_idx[7:1]}] <= add_host_dout;
                end else begin
                    u_mem0[{u_i, coeff_idx[7:1]}] <= add_host_dout;
                end
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
            if (state == S_V_ADDMSG_READ_CAP) begin
                if (coeff_idx[0]) begin
                    v_mem1[coeff_idx[7:1]] <= add_host_dout;
                end else begin
                    v_mem0[coeff_idx[7:1]] <= add_host_dout;
                end
            end
        end
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            msg_poly_rd_a0 <= 16'd0;
            msg_poly_rd_a1 <= 16'd0;
        end else begin
            msg_poly_rd_a0 <= msg_poly_mem0[msg_poly_rpair_addr];
            msg_poly_rd_a1 <= msg_poly_mem1[msg_poly_rpair_addr];
            if (frommsg_coeff_we) begin
                msg_poly_mem0[frommsg_coeff_addr] <= frommsg_coeff_a0;
                msg_poly_mem1[frommsg_coeff_addr] <= frommsg_coeff_a1;
            end
        end
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            r_hat_rdata <= 16'd0;
        end else begin
            r_hat_rdata <= r_hat_mem[r_hat_raddr];
            if (state == S_NTT_READ_CAP) begin
                r_hat_mem[{noise_idx, coeff_idx}] <= ntt_host_dout;
            end
        end
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            acc_rdata <= 16'd0;
        end else begin
            acc_rdata <= acc_mem[acc_raddr];

            // Option B: direct PW->ACC when j==0 or i==0
            if ((state == S_U_PW_READ_CAP) && (u_j == 2'd0)) begin
                acc_mem[coeff_idx] <= pw_host_dout;
            end else if ((state == S_V_PW_READ_CAP) && (v_i == 2'd0)) begin
                acc_mem[coeff_idx] <= pw_host_dout;
            end else if ((state == S_U_ACC_READ_CAP) || (state == S_V_ACC_READ_CAP)) begin
                acc_mem[coeff_idx] <= add_host_dout;
            end else if (state == S_V_ADDE2_READ_CAP) begin
                acc_mem[coeff_idx] <= add_host_dout;
            end
        end
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            tmp_rdata <= 16'd0;
        end else begin
            tmp_rdata <= tmp_mem[tmp_raddr];
            if (cbd_ram_we && (noise_stage == 2'd0)) begin
                tmp_mem[{cbd_ram_addr, 1'b0}] <= cbd_ram_a0_din;
                tmp_mem[{cbd_ram_addr, 1'b1}] <= cbd_ram_a1_din;
            end else if ((state == S_U_PW_READ_CAP) && (u_j != 2'd0)) begin
                tmp_mem[coeff_idx] <= pw_host_dout;
            end else if ((state == S_V_PW_READ_CAP) && (v_i != 2'd0)) begin
                tmp_mem[coeff_idx] <= pw_host_dout;
            end else if ((state == S_U_INTT_READ_CAP) || (state == S_V_INTT_READ_CAP)) begin
                tmp_mem[coeff_idx] <= intt_host_dout;
            end
        end
    end

    // =============================================================
    // Helper / derived control
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
            ct_rd_en         <= 1'b0;
            ct_rd_addr       <= 11'd0;
            ct_rd_pending    <= 1'b0;
            ct_rd_pending_d1 <= 1'b0;

            init_keccak      <= 1'b0;
            hash_type        <= 2'b00;
            finalize_keccak  <= 1'b0;
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
        end else begin
            done             <= 1'b0;
            out_valid        <= 1'b0;
            ct_rd_en         <= 1'b0;
            init_keccak      <= 1'b0;
            finalize_keccak  <= 1'b0;
            k_din_valid      <= 1'b0;
            cbd_start        <= 1'b0;
            parse_start      <= 1'b0;

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
                if (out_addr < 11'd1088) begin
                    ct_rd_en      <= 1'b1;
                    ct_rd_addr    <= out_addr;
                    ct_rd_pending <= 1'b1;
                end else begin
                    out_valid        <= 1'b1;
                    out_rdata        <= 8'd0;
                    ct_rd_pending    <= 1'b0;
                    ct_rd_pending_d1 <= 1'b0;
                end
            end

            case (state)
                S_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        busy             <= 1'b1;
                        ct_rd_pending    <= 1'b0;
                        ct_rd_pending_d1 <= 1'b0;
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
                        state            <= S_DECODE_EK_START;
                    end
                end

                // -------------------------------------------------
                // Decode EK (t_hat + rho)
                // -------------------------------------------------
                S_DECODE_EK_START: begin
                    state <= S_DECODE_EK_WAIT;
                end

                S_DECODE_EK_WAIT: begin
                    if (fromb_done) begin
                        if (decode_idx == 2'd2) begin
                            // rho_reg already populated at ek preload time
                            // (see byte-buffer always block above) so we can
                            // skip the legacy 32-way parallel read that used
                            // to live here and block BRAM inference on ek_buf.
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
                    if ((noise_stage == 2'd0) && (noise_idx == 2'd3)) begin
                        noise_stage <= 2'd1;
                        noise_idx   <= 2'd0;
                    end else if ((noise_stage == 2'd1) && (noise_idx == 2'd3)) begin
                        noise_stage <= 2'd2;
                        noise_idx   <= 2'd0;
                    end else if ((noise_stage == 2'd2) && (noise_idx == 2'd1)) begin
                        state <= S_FROMMSG_START;
                    end else begin
                        init_keccak <= 1'b1;
                        hash_type   <= 2'b01; // SHAKE256
                        var_k       <= 12'd0;
                        k_din       <= r_buf[5'd0];
                        k_din_valid <= 1'b1;
                        state       <= S_PRF_ABSORB;
                    end
                end

                S_PRF_ABSORB: begin
                    k_din_valid <= 1'b1;
                    if (k_din_ready) begin
                        if (var_k == 12'd32) begin
                            k_din_valid <= 1'b0;
                            var_k <= 12'd0;
                            state <= S_PRF_FINAL;
                        end else begin
                            var_k <= var_k + 12'd1;
                            if (var_k < 12'd31) begin
                                k_din <= r_buf[var_k[4:0] + 5'd1];
                            end else begin
                                k_din <= noise_nonce;
                            end
                        end
                    end
                end

                S_PRF_FINAL: begin
                    finalize_keccak <= 1'b1;
                    fsm_k_dout_ready <= 1'b1;
                    prf_word_idx    <= 4'd0;
                    prf_byte_idx    <= 3'd0;
                    prf_shift       <= 64'd0;
                    state           <= S_PRF_WAIT;
                end

                S_PRF_WAIT: begin
                    if (k_dout_valid && fsm_k_dout_ready) begin
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
                            state     <= S_NTT_LOAD_PREF;
                        end else begin
                            noise_idx <= noise_idx + 2'd1;
                            state     <= S_NOISE_INIT;
                        end
                    end
                end

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
                        noise_idx <= noise_idx + 2'd1;
                        state     <= S_NOISE_INIT;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state     <= S_NTT_READ_REQ;
                    end
                end

                // -------------------------------------------------
                // Message encoding
                // -------------------------------------------------
                S_FROMMSG_START: begin
                    state <= S_FROMMSG_WAIT;
                end

                S_FROMMSG_WAIT: begin
                    if (frommsg_done) begin
                        u_i <= 2'd0;
                        state <= S_U_INIT;
                    end
                end

                // -------------------------------------------------
                // U-loop: u[i] = INTT(sum_j A^T[i][j]*r_hat[j]) + e1[i]
                // -------------------------------------------------
                S_U_INIT: begin
                    u_j <= 2'd0;
                    state <= S_U_XOF_INIT;
                end

                S_U_XOF_INIT: begin
                    init_keccak <= 1'b1;
                    hash_type   <= 2'b00; // SHAKE128
                    var_k       <= 12'd0;
                    k_din       <= rho_reg[5'd0];
                    k_din_valid <= 1'b1;
                    state       <= S_U_XOF_ABSORB;
                end

                S_U_XOF_ABSORB: begin
                    k_din_valid <= 1'b1;
                    if (k_din_ready) begin
                        if (var_k == 12'd33) begin
                            k_din_valid <= 1'b0;
                            state <= S_U_XOF_FINAL;
                        end else begin
                            var_k <= var_k + 12'd1;
                            if (var_k < 12'd31) begin
                                k_din <= rho_reg[var_k[4:0] + 5'd1];
                            end else if (var_k == 12'd31) begin
                                k_din <= {6'd0, u_i}; // i first
                            end else begin
                                k_din <= {6'd0, u_j}; // j second
                            end
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
                        state <= S_U_PW_LOAD_A_PREF;
                    end
                end

                S_U_PW_LOAD_A_PREF: begin
                    coeff_idx <= 8'd0;
                    state <= S_U_PW_LOAD_A_LOOP;
                end

                S_U_PW_LOAD_A_LOOP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_U_PW_LOAD_B_PREF;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_U_PW_LOAD_B_PREF: begin
                    coeff_idx <= 8'd0;
                    state <= S_U_PW_LOAD_B_LOOP;
                end

                S_U_PW_LOAD_B_LOOP: begin
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
                            u_j <= 2'd1;
                            state <= S_U_XOF_INIT;
                        end else begin
                            state <= S_U_ACC_LOAD_A_PREF;
                        end
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state <= S_U_PW_READ_REQ;
                    end
                end

                S_U_ACC_LOAD_A_PREF: begin
                    coeff_idx <= 8'd0;
                    state <= S_U_ACC_LOAD_A_LOOP;
                end

                S_U_ACC_LOAD_A_LOOP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_U_ACC_LOAD_B_PREF;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_U_ACC_LOAD_B_PREF: begin
                    coeff_idx <= 8'd0;
                    state <= S_U_ACC_LOAD_B_LOOP;
                end

                S_U_ACC_LOAD_B_LOOP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_U_ACC_START;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_U_ACC_START: begin
                    state <= S_U_ACC_WAIT;
                end

                S_U_ACC_WAIT: begin
                    if (add_done) begin
                        coeff_idx <= 8'd0;
                        state <= S_U_ACC_READ_REQ;
                    end
                end

                S_U_ACC_READ_REQ: begin
                    state <= S_U_ACC_READ_CAP;
                end

                S_U_ACC_READ_CAP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        if (u_j == 2'd2) begin
                            state <= S_U_INTT_LOAD_PREF;
                        end else begin
                            u_j <= u_j + 2'd1;
                            state <= S_U_XOF_INIT;
                        end
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state <= S_U_ACC_READ_REQ;
                    end
                end

                S_U_INTT_LOAD_PREF: begin
                    coeff_idx <= 8'd0;
                    state <= S_U_INTT_LOAD_LOOP;
                end

                S_U_INTT_LOAD_LOOP: begin
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
                        state <= S_U_ADDE1_LOAD_A_PREF;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state <= S_U_INTT_READ_REQ;
                    end
                end

                S_U_ADDE1_LOAD_A_PREF: begin
                    coeff_idx <= 8'd0;
                    state <= S_U_ADDE1_LOAD_A_LOOP;
                end

                S_U_ADDE1_LOAD_A_LOOP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_U_ADDE1_LOAD_B_PREF;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_U_ADDE1_LOAD_B_PREF: begin
                    coeff_idx <= 8'd0;
                    state <= S_U_ADDE1_LOAD_B_LOOP;
                end

                S_U_ADDE1_LOAD_B_LOOP: begin
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
                // V-loop: v = INTT(sum_i t_hat[i]*r_hat[i]) + e2 + msg_poly
                // -------------------------------------------------
                S_V_INIT: begin
                    coeff_idx <= 8'd0;
                    state <= S_V_PW_LOAD_A_PREF;
                end

                S_V_PW_LOAD_A_PREF: begin
                    coeff_idx <= 8'd0;
                    state <= S_V_PW_LOAD_A_LOOP;
                end

                S_V_PW_LOAD_A_LOOP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_PW_LOAD_B_PREF;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_V_PW_LOAD_B_PREF: begin
                    coeff_idx <= 8'd0;
                    state <= S_V_PW_LOAD_B_LOOP;
                end

                S_V_PW_LOAD_B_LOOP: begin
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
                            v_i <= 2'd1;
                            state <= S_V_PW_LOAD_A_PREF;
                        end else begin
                            state <= S_V_ACC_LOAD_A_PREF;
                        end
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state <= S_V_PW_READ_REQ;
                    end
                end

                S_V_ACC_LOAD_A_PREF: begin
                    coeff_idx <= 8'd0;
                    state <= S_V_ACC_LOAD_A_LOOP;
                end

                S_V_ACC_LOAD_A_LOOP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_ACC_LOAD_B_PREF;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_V_ACC_LOAD_B_PREF: begin
                    coeff_idx <= 8'd0;
                    state <= S_V_ACC_LOAD_B_LOOP;
                end

                S_V_ACC_LOAD_B_LOOP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_ACC_START;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_V_ACC_START: begin
                    state <= S_V_ACC_WAIT;
                end

                S_V_ACC_WAIT: begin
                    if (add_done) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_ACC_READ_REQ;
                    end
                end

                S_V_ACC_READ_REQ: begin
                    state <= S_V_ACC_READ_CAP;
                end

                S_V_ACC_READ_CAP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        if (v_i == 2'd2) begin
                            state <= S_V_INTT_LOAD_PREF;
                        end else begin
                            v_i <= v_i + 2'd1;
                            state <= S_V_PW_LOAD_A_PREF;
                        end
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state <= S_V_ACC_READ_REQ;
                    end
                end

                S_V_INTT_LOAD_PREF: begin
                    coeff_idx <= 8'd0;
                    state <= S_V_INTT_LOAD_LOOP;
                end

                S_V_INTT_LOAD_LOOP: begin
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
                        state <= S_V_ADDE2_LOAD_A_PREF;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state <= S_V_INTT_READ_REQ;
                    end
                end

                S_V_ADDE2_LOAD_A_PREF: begin
                    coeff_idx <= 8'd0;
                    state <= S_V_ADDE2_LOAD_A_LOOP;
                end

                S_V_ADDE2_LOAD_A_LOOP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_ADDE2_LOAD_B_PREF;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_V_ADDE2_LOAD_B_PREF: begin
                    coeff_idx <= 8'd0;
                    state <= S_V_ADDE2_LOAD_B_LOOP;
                end

                S_V_ADDE2_LOAD_B_LOOP: begin
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
                        state <= S_V_ADDMSG_LOAD_A_PREF;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state <= S_V_ADDE2_READ_REQ;
                    end
                end

                S_V_ADDMSG_LOAD_A_PREF: begin
                    coeff_idx <= 8'd0;
                    state <= S_V_ADDMSG_LOAD_A_LOOP;
                end

                S_V_ADDMSG_LOAD_A_LOOP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state <= S_V_ADDMSG_LOAD_B_PREF;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
                end

                S_V_ADDMSG_LOAD_B_PREF: begin
                    coeff_idx <= 8'd0;
                    state <= S_V_ADDMSG_LOAD_B_LOOP;
                end

                S_V_ADDMSG_LOAD_B_LOOP: begin
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
                        state            <= S_COMP_U_PREF;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state <= S_V_ADDMSG_READ_REQ;
                    end
                end

                // -------------------------------------------------
                // Compression
                // -------------------------------------------------
                S_COMP_U_PREF: begin
                    state <= S_COMP_U_START;
                end

                S_COMP_U_START: begin
                    state <= S_COMP_U_WAIT;
                end

                S_COMP_U_WAIT: begin
                    if (comp_done) begin
                        if (comp_u_idx == 2'd2) begin
                            comp_mode_v      <= 1'b1;
                            comp_d_sel_reg   <= 2'b01; // d=4
                            comp_base_offset <= 11'd960;
                            state            <= S_COMP_V_PREF;
                        end else begin
                            comp_u_idx       <= comp_u_idx + 2'd1;
                            comp_base_offset <= comp_base_offset + 11'd320;
                            state            <= S_COMP_U_PREF;
                        end
                    end
                end

                S_COMP_V_PREF: begin
                    state <= S_COMP_V_START;
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
