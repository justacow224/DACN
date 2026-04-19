`timescale 1ns / 1ps

module ml_kem_decaps (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    output reg          busy,
    output reg          done,

    // Input preload
    // in_sel = 0: dk (2400 bytes)
    // in_sel = 1: ct (1088 bytes)
    input  wire         in_we,
    input  wire         in_sel,
    input  wire [11:0]  in_addr,
    input  wire [7:0]   in_wdata,

    // Output readback (shared secret)
    input  wire         out_rd,
    input  wire [10:0]  out_addr,
    output reg  [7:0]   out_rdata,
    output reg          out_valid,

    // Packed shared secret output
    output reg  [255:0] ss_out
);

    localparam [4:0] S_IDLE          = 5'd0;
    localparam [4:0] S_DEC_PRELOAD   = 5'd1;
    localparam [4:0] S_DEC_START     = 5'd2;
    localparam [4:0] S_DEC_WAIT      = 5'd3;
    localparam [4:0] S_CAPTURE_M     = 5'd4;
    localparam [4:0] S_HASH_G_INIT   = 5'd5;
    localparam [4:0] S_HASH_G_ABS    = 5'd6;
    localparam [4:0] S_HASH_G_FIN    = 5'd7;
    localparam [4:0] S_HASH_G_WAIT   = 5'd8;
    localparam [4:0] S_HASH_J_INIT   = 5'd9;
    localparam [4:0] S_HASH_J_ABS    = 5'd10;
    localparam [4:0] S_HASH_J_FIN    = 5'd11;
    localparam [4:0] S_HASH_J_WAIT   = 5'd12;
    localparam [4:0] S_ENC_PRELOAD   = 5'd13;
    localparam [4:0] S_ENC_START     = 5'd14;
    localparam [4:0] S_ENC_WAIT      = 5'd15;
    localparam [4:0] S_ENC_SETTLE    = 5'd16;
    localparam [4:0] S_COMPARE_INIT  = 5'd17;
    localparam [4:0] S_COMPARE       = 5'd18;
    localparam [4:0] S_OUTPUT        = 5'd19;
    localparam [4:0] S_ZEROIZE       = 5'd20;
    localparam [4:0] S_DONE          = 5'd21;

    reg [4:0] state;

    (* ram_style = "block" *) reg [7:0] dk_buf       [0:2399];
    (* ram_style = "block" *) reg [7:0] ct_buf       [0:1087];
    (* ram_style = "block" *) reg [7:0] ct_prime_buf [0:1087];

    reg [7:0] m_prime  [0:31];
    reg [7:0] k_prime  [0:31];
    reg [7:0] r_prime  [0:31];
    reg [7:0] k_reject [0:31];
    reg [7:0] ss_buf   [0:31];

    reg         init_keccak;
    reg  [1:0]  hash_type;
    reg         finalize_keccak;
    reg  [7:0]  k_din;
    reg         k_din_valid;
    wire        k_din_ready;
    wire [7:0]  k_dout;
    wire        k_dout_valid;
    reg         fsm_k_dout_ready;

    reg         dec_start;
    reg         dec_in_we;
    reg         dec_in_sel;
    reg  [10:0] dec_in_addr;
    reg  [7:0]  dec_in_wdata;
    wire        dec_busy;
    wire        dec_done;
    wire [255:0] dec_m_out;

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

    reg [11:0] var_k;
    reg [7:0]  xor_acc;
    reg        match_reg;

    wire [7:0] compare_xor_byte = ct_buf[var_k[10:0]] ^ ct_prime_buf[var_k[10:0]];
    wire [7:0] compare_xor_next = xor_acc | compare_xor_byte;
    wire [7:0] match_mask = {8{match_reg}};

    integer i;

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
        .dout_ready(fsm_k_dout_ready)
    );

    kpke_decrypt u_decrypt (
        .clk(clk),
        .rst_n(rst_n),
        .start(dec_start),
        .busy(dec_busy),
        .done(dec_done),
        .in_we(dec_in_we),
        .in_sel(dec_in_sel),
        .in_addr(dec_in_addr),
        .in_wdata(dec_in_wdata),
        .out_rd(1'b0),
        .out_addr(5'd0),
        .out_rdata(),
        .out_valid(),
        .msg_we(),
        .msg_addr(),
        .msg_dout(),
        .m_out(dec_m_out)
    );

    kpke_encrypt u_encrypt (
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
        .ct_dout(enc_ct_dout)
    );

    // Input preload memories for decaps top
    always @(posedge clk) begin
        if (in_we && !busy) begin
            if (!in_sel) begin
                if (in_addr < 12'd2400) begin
                    dk_buf[in_addr] <= in_wdata;
                end
            end else begin
                if (in_addr < 12'd1088) begin
                    ct_buf[in_addr[10:0]] <= in_wdata;
                end
            end
        end
    end

    // Capture re-encryption ciphertext stream
    always @(posedge clk) begin
        if (enc_ct_we && (enc_ct_addr < 11'd1088)) begin
            ct_prime_buf[enc_ct_addr] <= enc_ct_dout;
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state            <= S_IDLE;
            busy             <= 1'b0;
            done             <= 1'b0;
            out_rdata        <= 8'd0;
            out_valid        <= 1'b0;
            ss_out           <= 256'd0;

            init_keccak      <= 1'b0;
            hash_type        <= 2'b00;
            finalize_keccak  <= 1'b0;
            k_din            <= 8'd0;
            k_din_valid      <= 1'b0;
            fsm_k_dout_ready <= 1'b0;

            dec_start        <= 1'b0;
            dec_in_we        <= 1'b0;
            dec_in_sel       <= 1'b0;
            dec_in_addr      <= 11'd0;
            dec_in_wdata     <= 8'd0;

            enc_start        <= 1'b0;
            enc_in_we        <= 1'b0;
            enc_in_sel       <= 2'd0;
            enc_in_addr      <= 11'd0;
            enc_in_wdata     <= 8'd0;

            var_k            <= 12'd0;
            xor_acc          <= 8'd0;
            match_reg        <= 1'b0;
        end else begin
            done             <= 1'b0;
            out_valid        <= 1'b0;
            init_keccak      <= 1'b0;
            finalize_keccak  <= 1'b0;
            k_din_valid      <= 1'b0;
            dec_start        <= 1'b0;
            dec_in_we        <= 1'b0;
            enc_start        <= 1'b0;
            enc_in_we        <= 1'b0;

            if (out_rd) begin
                out_valid <= 1'b1;
                if (out_addr < 11'd32) out_rdata <= ss_buf[out_addr[4:0]];
                else                    out_rdata <= 8'd0;
            end

            case (state)
                S_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        busy    <= 1'b1;
                        var_k   <= 12'd0;
                        xor_acc <= 8'd0;
                        match_reg <= 1'b0;
                        for (i = 0; i < 32; i = i + 1) begin
                            m_prime[i]  <= 8'd0;
                            k_prime[i]  <= 8'd0;
                            r_prime[i]  <= 8'd0;
                            k_reject[i] <= 8'd0;
                            ss_buf[i]   <= 8'd0;
                            ss_out[i*8 +: 8] <= 8'd0;
                        end
                        for (i = 0; i < 1088; i = i + 1) begin
                            ct_prime_buf[i] <= 8'd0;
                        end
                        state <= S_DEC_PRELOAD;
                    end
                end

                // Preload kpke_decrypt with dk_PKE || ct
                S_DEC_PRELOAD: begin
                    dec_in_we <= 1'b1;
                    if (var_k < 12'd1152) begin
                        dec_in_sel   <= 1'b0;
                        dec_in_addr  <= var_k[10:0];
                        dec_in_wdata <= dk_buf[var_k];
                        var_k        <= var_k + 12'd1;
                    end else if (var_k < 12'd2240) begin
                        dec_in_sel   <= 1'b1;
                        dec_in_addr  <= var_k[10:0] - 11'd1152;
                        dec_in_wdata <= ct_buf[var_k - 12'd1152];
                        if (var_k == 12'd2239) begin
                            var_k <= 12'd0;
                            state <= S_DEC_START;
                        end else begin
                            var_k <= var_k + 12'd1;
                        end
                    end else begin
                        var_k <= 12'd0;
                        state <= S_DEC_START;
                    end
                end

                S_DEC_START: begin
                    dec_start <= 1'b1;
                    state <= S_DEC_WAIT;
                end

                S_DEC_WAIT: begin
                    if (dec_done) begin
                        state <= S_CAPTURE_M;
                    end
                end

                S_CAPTURE_M: begin
                    for (i = 0; i < 32; i = i + 1) begin
                        m_prime[i] <= dec_m_out[i*8 +: 8];
                    end
                    var_k <= 12'd0;
                    state <= S_HASH_G_INIT;
                end

                // (K', r') = SHA3-512(m' || h)
                S_HASH_G_INIT: begin
                    init_keccak <= 1'b1;
                    hash_type   <= 2'b11; // SHA3-512
                    var_k       <= 12'd0;
                    k_din       <= m_prime[5'd0];
                    k_din_valid <= 1'b1;
                    state       <= S_HASH_G_ABS;
                end

                S_HASH_G_ABS: begin
                    k_din_valid <= 1'b1;
                    if (k_din_ready) begin
                        if (var_k == 12'd63) begin
                            k_din_valid <= 1'b0;
                            state <= S_HASH_G_FIN;
                        end else begin
                            var_k <= var_k + 12'd1;
                            if (var_k < 12'd31) begin
                                k_din <= m_prime[var_k[4:0] + 5'd1];
                            end else begin
                                k_din <= dk_buf[12'd2336 + (var_k - 12'd31)];
                            end
                        end
                    end
                end

                S_HASH_G_FIN: begin
                    finalize_keccak  <= 1'b1;
                    fsm_k_dout_ready <= 1'b1;
                    var_k            <= 12'd0;
                    state            <= S_HASH_G_WAIT;
                end

                S_HASH_G_WAIT: begin
                    if (k_dout_valid && fsm_k_dout_ready) begin
                        if (var_k < 12'd32) begin
                            k_prime[var_k[4:0]] <= k_dout;
                        end else begin
                            r_prime[var_k - 12'd32] <= k_dout;
                        end
                        if (var_k == 12'd63) begin
                            fsm_k_dout_ready <= 1'b0;
                            var_k <= 12'd0;
                            state <= S_HASH_J_INIT;
                        end else begin
                            var_k <= var_k + 12'd1;
                        end
                    end
                end

                // K_reject = SHAKE-256(z || ct)
                S_HASH_J_INIT: begin
                    init_keccak <= 1'b1;
                    hash_type   <= 2'b01; // SHAKE-256
                    var_k       <= 12'd0;
                    k_din       <= dk_buf[12'd2368];
                    k_din_valid <= 1'b1;
                    state       <= S_HASH_J_ABS;
                end

                S_HASH_J_ABS: begin
                    k_din_valid <= 1'b1;
                    if (k_din_ready) begin
                        if (var_k == 12'd1119) begin
                            k_din_valid <= 1'b0;
                            state <= S_HASH_J_FIN;
                        end else begin
                            var_k <= var_k + 12'd1;
                            if (var_k < 12'd31) begin
                                k_din <= dk_buf[12'd2368 + var_k + 12'd1];
                            end else begin
                                k_din <= ct_buf[var_k - 12'd31];
                            end
                        end
                    end
                end

                S_HASH_J_FIN: begin
                    finalize_keccak  <= 1'b1;
                    fsm_k_dout_ready <= 1'b1;
                    var_k            <= 12'd0;
                    state            <= S_HASH_J_WAIT;
                end

                S_HASH_J_WAIT: begin
                    if (k_dout_valid && fsm_k_dout_ready) begin
                        k_reject[var_k[4:0]] <= k_dout;
                        if (var_k == 12'd31) begin
                            fsm_k_dout_ready <= 1'b0;
                            var_k <= 12'd0;
                            state <= S_ENC_PRELOAD;
                        end else begin
                            var_k <= var_k + 12'd1;
                        end
                    end
                end

                // Preload kpke_encrypt with ek || m' || r'
                S_ENC_PRELOAD: begin
                    enc_in_we <= 1'b1;
                    if (var_k < 12'd1184) begin
                        enc_in_sel   <= 2'd0;
                        enc_in_addr  <= var_k[10:0];
                        enc_in_wdata <= dk_buf[12'd1152 + var_k];
                        var_k        <= var_k + 12'd1;
                    end else if (var_k < 12'd1216) begin
                        enc_in_sel   <= 2'd1;
                        enc_in_addr  <= var_k[10:0] - 11'd1184;
                        enc_in_wdata <= m_prime[var_k - 12'd1184];
                        var_k        <= var_k + 12'd1;
                    end else if (var_k < 12'd1248) begin
                        enc_in_sel   <= 2'd2;
                        enc_in_addr  <= var_k[10:0] - 11'd1216;
                        enc_in_wdata <= r_prime[var_k - 12'd1216];
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

                S_ENC_START: begin
                    enc_start <= 1'b1;
                    state <= S_ENC_WAIT;
                end

                S_ENC_WAIT: begin
                    if (enc_done) begin
                        var_k <= 12'd0;
                        state <= S_ENC_SETTLE;
                    end
                end

                S_ENC_SETTLE: begin
                    if (var_k == 12'd2) begin
                        state <= S_COMPARE_INIT;
                    end else begin
                        var_k <= var_k + 12'd1;
                    end
                end

                // Constant-time compare: XOR-accumulate all 1088 bytes
                S_COMPARE_INIT: begin
                    xor_acc <= 8'd0;
                    var_k   <= 12'd0;
                    state   <= S_COMPARE;
                end

                S_COMPARE: begin
                    xor_acc <= compare_xor_next;
                    if (var_k == 12'd1087) begin
                        match_reg <= (compare_xor_next == 8'd0);
                        var_k <= 12'd0;
                        state <= S_OUTPUT;
                    end else begin
                        var_k <= var_k + 12'd1;
                    end
                end

                // Constant-time MUX output
                S_OUTPUT: begin
                    ss_buf[var_k[4:0]] <= (k_prime[var_k[4:0]] & match_mask) |
                                          (k_reject[var_k[4:0]] & ~match_mask);
                    ss_out[var_k[4:0]*8 +: 8] <= (k_prime[var_k[4:0]] & match_mask) |
                                                 (k_reject[var_k[4:0]] & ~match_mask);
                    if (var_k == 12'd31) begin
                        var_k <= 12'd0;
                        state <= S_ZEROIZE;
                    end else begin
                        var_k <= var_k + 12'd1;
                    end
                end

                // Zeroize sensitive intermediates
                S_ZEROIZE: begin
                    m_prime[var_k[4:0]] <= 8'd0;
                    r_prime[var_k[4:0]] <= 8'd0;
                    k_prime[var_k[4:0]] <= 8'd0;
                    if (var_k == 12'd31) begin
                        var_k <= 12'd0;
                        state <= S_DONE;
                    end else begin
                        var_k <= var_k + 12'd1;
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
