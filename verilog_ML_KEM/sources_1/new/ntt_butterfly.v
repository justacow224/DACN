`timescale 1ns / 1ps

module ntt_butterfly (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         en,
    input  wire [15:0]  a,
    input  wire [15:0]  b,
    input  wire [15:0]  zeta,
    output reg  [15:0]  a_prime,
    output reg  [15:0]  b_prime
);

    localparam [11:0] KYBER_Q = 12'd3329;

    // =========================================================
    // 1. MODULAR MULTIPLIER (4 cycles latency)
    // =========================================================
    wire [15:0] t_wire_16;
    mul_mod u_mul_mod (
        .clk(clk),
        .rst_n(rst_n),
        .en(en),
        .a(b),          
        .b(zeta),       
        .res(t_wire_16)  // Guaranteed to be in [0, 3328]
    );

    // Only 12 bits are needed for values <= 3328
    wire [11:0] t_val = t_wire_16[11:0];

    // =========================================================
    // 2. DELAY SHIFT REGISTER FOR 'a' (4 cycles latency)
    // OPTIMIZATION: Truncate from 16-bit to 12-bit to save 
    // exactly 16 Flip-Flops in the pipeline.
    // =========================================================
    reg [11:0] a_delay_1, a_delay_2, a_delay_3, a_delay_4;
    
    always @(posedge clk) begin
        if (!rst_n) begin
            a_delay_1 <= 12'd0;
            a_delay_2 <= 12'd0;
            a_delay_3 <= 12'd0;
            a_delay_4 <= 12'd0;
        end else if (en) begin
            a_delay_1 <= a[11:0];
            a_delay_2 <= a_delay_1;
            a_delay_3 <= a_delay_2;
            a_delay_4 <= a_delay_3;
        end
    end

    // =========================================================
    // 3. STAGE 5: ADD/SUB MODULO (1 cycle latency)
    // OPTIMIZATION: Using 13-bit intermediate wire forces the 
    // synthesis tool to infer smaller, faster adders.
    // =========================================================
    wire [12:0] sum = a_delay_4 + t_val;
    
    always @(posedge clk) begin
        if (!rst_n) begin
            a_prime <= 16'd0;
            b_prime <= 16'd0;
        end else if (en) begin
            
            // a_prime = (a + t) mod Q
            // Zero-pad the upper 4 bits back to 16-bit interface
            if (sum >= KYBER_Q)
                a_prime <= {4'd0, sum - KYBER_Q};
            else
                a_prime <= {4'd0, sum[11:0]};

            // b_prime = (a - t) mod Q 
            // Absolute anti-underflow with pure unsigned logic
            if (a_delay_4 >= t_val)
                b_prime <= {4'd0, a_delay_4 - t_val};
            else
                b_prime <= {4'd0, a_delay_4 + KYBER_Q - t_val};
        end
    end

endmodule
