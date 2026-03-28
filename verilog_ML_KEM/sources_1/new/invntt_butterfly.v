`timescale 1ns / 1ps

module invntt_butterfly (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         en,
    input  wire [15:0]  a,
    input  wire [15:0]  b,
    input  wire [15:0]  inv_zeta,
    output reg  [15:0]  a_prime,
    output wire [15:0]  b_prime
);

    localparam [11:0] KYBER_Q = 12'd3329;

    // =========================================================
    // 1. STAGE 1: ADD / SUB MODULO (1 cycle latency)
    // =========================================================
    reg [11:0] sum_reg;
    reg [11:0] diff_reg;
    
    // OPTIMIZATION: Reduce twiddle factor register to 12-bit 
    // to save 4 Flip-Flops.
    reg [11:0] inv_zeta_reg;

    // Use 13-bit wire to infer optimal, small adder
    wire [12:0] sum = a[11:0] + b[11:0];

    always @(posedge clk) begin
        if (en) begin
            // a_prime_temp = (a + b) mod Q
            if (sum >= KYBER_Q)
                sum_reg <= sum - KYBER_Q;
            else
                sum_reg <= sum[11:0];

            // diff = (a - b) mod Q (pure unsigned anti-underflow)
            if (a[11:0] >= b[11:0])
                diff_reg <= a[11:0] - b[11:0];
            else
                diff_reg <= a[11:0] + KYBER_Q - b[11:0];

            // Truncate to 12-bit
            inv_zeta_reg <= inv_zeta[11:0];
        end
    end

    // =========================================================
    // 2. STAGE 2: MODULAR MULTIPLIER (4 cycles latency)
    // =========================================================
    mul_mod u_mul_mod (
        .clk(clk),
        .rst_n(rst_n),
        .en(en),
        .a({4'd0, diff_reg}),      // Zero-pad to match 16-bit port
        .b({4'd0, inv_zeta_reg}),  // Zero-pad to match 16-bit port
        .res(b_prime)              // Multiplier guarantees result in [0, 3328]
    );

    // =========================================================
    // 3. SHIFT REGISTER FOR 'a_prime' (3 cycles delay)
    // Total delay for a_prime = 1 (Stage 1) + 3 (Shift) + 1 (Output) = 5 cycles.
    // Matches b_prime perfectly: 1 (Stage 1) + 4 (mul_mod) = 5 cycles.
    // OPTIMIZATION: 12-bit shift register saves 12 Flip-Flops.
    // =========================================================
    reg [11:0] sum_delay_1, sum_delay_2, sum_delay_3;

    always @(posedge clk) begin
        if (!rst_n) begin
            a_prime <= 16'd0;
        end else if (en) begin
            sum_delay_1 <= sum_reg;
            sum_delay_2 <= sum_delay_1;
            sum_delay_3 <= sum_delay_2;
            
            // Zero-pad back to 16-bit for output
            a_prime     <= {4'd0, sum_delay_3};
        end
    end

endmodule