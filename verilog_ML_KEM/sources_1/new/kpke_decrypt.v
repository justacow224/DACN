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

    reg [5:0] state;

    // =============================================================
    // Input / Output byte buffers
    // =============================================================
    (* ram_style = "block" *) reg [7:0] dk_buf  [0:1151];
    (* ram_style = "block" *) reg [7:0] ct_buf  [0:1087];
    (* ram_style = "block" *) reg [7:0] msg_buf [0:31];

    // =============================================================
    // Internal memories
    // =============================================================
    (* ram_style = "block" *) reg [15:0] s_hat_mem   [0:767];  // 3 * 256
    (* ram_style = "block" *) reg [15:0] u_poly_mem  [0:767];  // decompressed u
    (* ram_style = "block" *) reg [15:0] u_hat_mem   [0:767];  // NTT(u)

    (* ram_style = "block" *) reg [15:0] v_mem       [0:255];
    (* ram_style = "block" *) reg [15:0] acc_mem     [0:255];
    (* ram_style = "block" *) reg [15:0] tmp_mem     [0:255];
    (* ram_style = "block" *) reg [15:0] w_mem       [0:255];
    (* ram_style = "block" *) reg [15:0] diff_mem    [0:255];

    // =============================================================
    // Control registers / indices
    // =============================================================
    reg [1:0] sk_idx;
    reg [1:0] dec_u_idx;
    reg       dec_phase_v;

    reg [1:0] ntt_idx;
    reg [1:0] pw_idx;

    reg [7:0] coeff_idx;
    integer clr_i;

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
    assign ntt_host_din  = u_poly_mem[{ntt_idx, coeff_idx}];

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

    assign pw_host_din = (state == S_PW_LOAD_A_LOOP) ? s_hat_mem[{pw_idx, coeff_idx}] :
                         (state == S_PW_LOAD_B_LOOP) ? u_hat_mem[{pw_idx, coeff_idx}] :
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

    assign add_host_din = (state == S_ADDACC_LOAD_A_LOOP) ? acc_mem[coeff_idx] :
                          (state == S_ADDACC_LOAD_B_LOOP) ? tmp_mem[coeff_idx] :
                          (state == S_SUB_LOAD_A_LOOP)    ? v_mem[coeff_idx]   :
                          (state == S_SUB_LOAD_B_LOOP)    ? w_mem[coeff_idx]   :
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
    assign intt_host_din  = acc_mem[coeff_idx];

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
    reg [15:0] comp_coeff_a0_r;
    reg [15:0] comp_coeff_a1_r;

    assign fromb_byte_din = fromb_byte_din_r;
    assign decomp_byte_din = decomp_byte_din_r;
    assign comp_coeff_a0 = comp_coeff_a0_r;
    assign comp_coeff_a1 = comp_coeff_a1_r;

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
            fromb_byte_din_r <= 8'd0;
            decomp_byte_din_r <= 8'd0;
            comp_coeff_a0_r <= 16'd0;
            comp_coeff_a1_r <= 16'd0;
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

            // 1-cycle registered readback to match module-side timing assumptions
            fromb_byte_din_r <= dk_buf[fromb_abs_addr];
            decomp_byte_din_r <= ct_buf[decomp_abs_addr];
            comp_coeff_a0_r <= diff_mem[{comp_coeff_addr, 1'b0}];
            comp_coeff_a1_r <= diff_mem[{comp_coeff_addr, 1'b1}];

            if (in_we && !busy) begin
                if (!in_sel) begin
                    if (in_addr < 11'd1152) dk_buf[in_addr] <= in_wdata;
                end else begin
                    if (in_addr < 11'd1088) ct_buf[in_addr] <= in_wdata;
                end
            end

            if (out_rd) begin
                out_valid <= 1'b1;
                if (out_addr <= 5'd31) out_rdata <= msg_buf[out_addr];
                else                   out_rdata <= 8'd0;
            end

            // -----------------------------------------------------
            // Capture datapath outputs
            // -----------------------------------------------------
            if (fromb_coeff_we) begin
                s_hat_mem[{sk_idx, fromb_coeff_addr, 1'b0}] <= fromb_coeff_a0;
                s_hat_mem[{sk_idx, fromb_coeff_addr, 1'b1}] <= fromb_coeff_a1;
            end

            if (decomp_coeff_we) begin
                if (dec_phase_v) begin
                    v_mem[{decomp_coeff_addr, 1'b0}] <= decomp_coeff_a0;
                    v_mem[{decomp_coeff_addr, 1'b1}] <= decomp_coeff_a1;
                end else begin
                    u_poly_mem[{dec_u_idx, decomp_coeff_addr, 1'b0}] <= decomp_coeff_a0;
                    u_poly_mem[{dec_u_idx, decomp_coeff_addr, 1'b1}] <= decomp_coeff_a1;
                end
            end

            if (state == S_NTT_READ_CAP) begin
                u_hat_mem[{ntt_idx, coeff_idx}] <= ntt_host_dout;
            end

            if (state == S_PW_READ_CAP) begin
                if (pw_idx == 2'd0)
                    acc_mem[coeff_idx] <= pw_host_dout;
                else
                    tmp_mem[coeff_idx] <= pw_host_dout;
            end

            if (state == S_ADDACC_READ_CAP) begin
                acc_mem[coeff_idx] <= add_host_dout;
            end

            if (state == S_INTT_READ_CAP) begin
                w_mem[coeff_idx] <= intt_host_dout;
            end

            if (state == S_SUB_READ_CAP) begin
                diff_mem[coeff_idx] <= add_host_dout;
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
                        state     <= S_NTT_LOAD_LOOP;
                    end
                end

                // NTT(u[i]) loop
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
                            state  <= S_PW_LOAD_A_LOOP;
                        end else begin
                            ntt_idx <= ntt_idx + 2'd1;
                            state   <= S_NTT_LOAD_LOOP;
                        end
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state     <= S_NTT_READ_REQ;
                    end
                end

                // Pointwise s_hat[i] * u_hat[i]
                S_PW_LOAD_A_LOOP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state     <= S_PW_LOAD_B_LOOP;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
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
                            state  <= S_PW_LOAD_A_LOOP;
                        end else begin
                            state <= S_ADDACC_LOAD_A_LOOP;
                        end
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state     <= S_PW_READ_REQ;
                    end
                end

                // acc += tmp for i=1,2
                S_ADDACC_LOAD_A_LOOP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state     <= S_ADDACC_LOAD_B_LOOP;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
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
                            state <= S_INTT_LOAD_LOOP;
                        end else begin
                            pw_idx <= pw_idx + 2'd1;
                            state  <= S_PW_LOAD_A_LOOP;
                        end
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state     <= S_ADDACC_READ_REQ;
                    end
                end

                // INTT(acc) -> w
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
                        state     <= S_SUB_LOAD_A_LOOP;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state     <= S_INTT_READ_REQ;
                    end
                end

                // diff = v - w
                S_SUB_LOAD_A_LOOP: begin
                    if (coeff_idx == 8'd255) begin
                        coeff_idx <= 8'd0;
                        state     <= S_SUB_LOAD_B_LOOP;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                    end
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
                        state <= S_COMP_START;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state     <= S_SUB_READ_REQ;
                    end
                end

                // Compress_1(diff) -> m
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
