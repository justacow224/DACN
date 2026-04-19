`timescale 1ns / 1ps

module ml_kem_encaps (
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
    output reg  [255:0] ss_out
);

    localparam [3:0] S_IDLE        = 4'd0;
    localparam [3:0] S_HASH_H_INIT = 4'd1;
    localparam [3:0] S_HASH_H_ABS  = 4'd2;
    localparam [3:0] S_HASH_H_FIN  = 4'd3;
    localparam [3:0] S_HASH_H_WAIT = 4'd4;
    localparam [3:0] S_HASH_G_INIT = 4'd5;
    localparam [3:0] S_HASH_G_ABS  = 4'd6;
    localparam [3:0] S_HASH_G_FIN  = 4'd7;
    localparam [3:0] S_HASH_G_WAIT = 4'd8;
    localparam [3:0] S_ENC_PRELOAD = 4'd9;
    localparam [3:0] S_ENC_START   = 4'd10;
    localparam [3:0] S_ENC_WAIT    = 4'd11;
    localparam [3:0] S_DONE        = 4'd12;

    reg [3:0] state;

    (* ram_style = "block" *) reg [7:0] ek_buf [0:1183];
    (* ram_style = "block" *) reg [7:0] m_buf  [0:31];
    (* ram_style = "block" *) reg [7:0] ct_buf [0:1087];

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
    integer i;

    assign ct_we   = enc_ct_we;
    assign ct_addr = enc_ct_addr;
    assign ct_dout = enc_ct_dout;

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

    // Keep byte-memory writes separate from FSM control for clearer BRAM inference.
    always @(posedge clk) begin
        if (in_we && !busy) begin
            if (!in_sel) begin
                if (in_addr < 11'd1184) begin
                    ek_buf[in_addr] <= in_wdata;
                end
            end else begin
                if (in_addr < 11'd32) begin
                    m_buf[in_addr[4:0]] <= in_wdata;
                end
            end
        end
    end

    always @(posedge clk) begin
        if (enc_ct_we && (enc_ct_addr < 11'd1088)) begin
            ct_buf[enc_ct_addr] <= enc_ct_dout;
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

            enc_start        <= 1'b0;
            enc_in_we        <= 1'b0;
            enc_in_sel       <= 2'd0;
            enc_in_addr      <= 11'd0;
            enc_in_wdata     <= 8'd0;

            var_k            <= 12'd0;
        end else begin
            done             <= 1'b0;
            out_valid        <= 1'b0;
            init_keccak      <= 1'b0;
            finalize_keccak  <= 1'b0;
            k_din_valid      <= 1'b0;
            enc_start        <= 1'b0;
            enc_in_we        <= 1'b0;

            if (out_rd) begin
                out_valid <= 1'b1;
                if (!out_sel) begin
                    if (out_addr < 11'd1088) out_rdata <= ct_buf[out_addr];
                    else                      out_rdata <= 8'd0;
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
                        state <= S_HASH_H_INIT;
                    end
                end

                // h = SHA3-256(ek)
                S_HASH_H_INIT: begin
                    init_keccak <= 1'b1;
                    hash_type   <= 2'b10; // SHA3-256
                    var_k       <= 12'd0;
                    k_din       <= ek_buf[11'd0];
                    k_din_valid <= 1'b1;
                    state       <= S_HASH_H_ABS;
                end

                S_HASH_H_ABS: begin
                    k_din_valid <= 1'b1;
                    if (k_din_ready) begin
                        if (var_k == 12'd1183) begin
                            k_din_valid <= 1'b0;
                            state <= S_HASH_H_FIN;
                        end else begin
                            var_k       <= var_k + 12'd1;
                            k_din       <= ek_buf[var_k + 12'd1];
                        end
                    end
                end

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
                    init_keccak <= 1'b1;
                    hash_type   <= 2'b11; // SHA3-512
                    var_k       <= 12'd0;
                    k_din       <= m_buf[5'd0];
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
                    enc_in_we <= 1'b1;
                    if (var_k < 12'd1184) begin
                        enc_in_sel   <= 2'd0;
                        enc_in_addr  <= var_k[10:0];
                        enc_in_wdata <= ek_buf[var_k[10:0]];
                        var_k        <= var_k + 12'd1;
                    end else if (var_k < 12'd1216) begin
                        enc_in_sel   <= 2'd1;
                        enc_in_addr  <= var_k[10:0] - 11'd1184;
                        enc_in_wdata <= m_buf[var_k - 12'd1184];
                        var_k        <= var_k + 12'd1;
                    end else if (var_k < 12'd1248) begin
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
