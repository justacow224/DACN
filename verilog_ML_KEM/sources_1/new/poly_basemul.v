`timescale 1ns / 1ps

module poly_basemul (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         en,
    input  wire [15:0]  a0,
    input  wire [15:0]  a1,
    input  wire [15:0]  b0,
    input  wire [15:0]  b1,
    input  wire [15:0]  gamma,
    output reg  [15:0]  c0_out,
    output reg  [15:0]  c1_out
);

    localparam [12:0] KYBER_Q = 13'd3329;

    // =========================================================
    // STAGE 1: FIRST MULTIPLIER LAYER (Latency: 4 cycles)
    // =========================================================
    wire [15:0] term1_w, term2_w, term4_w, term5_w;

    // term1 = a0 * b0
    mul_mod u_mul_term1 (.clk(clk), .rst_n(rst_n), .en(en), .a(a0), .b(b0), .res(term1_w));
    
    // term2 = a1 * b1
    mul_mod u_mul_term2 (.clk(clk), .rst_n(rst_n), .en(en), .a(a1), .b(b1), .res(term2_w));
    
    // term4 = a0 * b1
    mul_mod u_mul_term4 (.clk(clk), .rst_n(rst_n), .en(en), .a(a0), .b(b1), .res(term4_w));
    
    // term5 = a1 * b0
    mul_mod u_mul_term5 (.clk(clk), .rst_n(rst_n), .en(en), .a(a1), .b(b0), .res(term5_w));

    // Delay 'gamma' by 4 cycles so it arrives perfectly in sync with term2_w
    reg [11:0] gamma_d [0:3];
    integer i_gamma;
    always @(posedge clk) begin
        if (!rst_n) begin
            for (i_gamma = 0; i_gamma < 4; i_gamma = i_gamma + 1) begin
                gamma_d[i_gamma] <= 12'd0;
            end
        end else if (en) begin
            gamma_d[0] <= gamma[11:0];
            for (i_gamma = 1; i_gamma < 4; i_gamma = i_gamma + 1) begin
                gamma_d[i_gamma] <= gamma_d[i_gamma-1];
            end
        end
    end

    // =========================================================
    // STAGE 2: SECOND MULTIPLIER LAYER (Latency: 4 cycles)
    // =========================================================
    wire [15:0] term3_w;
    
    // term3 = term2 * gamma (Total latency from start = 4 + 4 = 8 cycles)
    mul_mod u_mul_term3 (
        .clk(clk),
        .rst_n(rst_n),
        .en(en),
        .a(term2_w),
        .b({4'd0, gamma_d[3]}), // Zero-pad to 16-bit
        .res(term3_w)
    );

    // We must delay term1, term4, and term5 by 4 more cycles 
    // to wait for term3 to finish multiplying.
    reg [11:0] term1_d [0:3];
    reg [11:0] term4_d [0:3];
    reg [11:0] term5_d [0:3];
    
    integer i_term;
    always @(posedge clk) begin
        if (!rst_n) begin
            for (i_term = 0; i_term < 4; i_term = i_term + 1) begin
                term1_d[i_term] <= 12'd0;
                term4_d[i_term] <= 12'd0;
                term5_d[i_term] <= 12'd0;
            end
        end else if (en) begin
            term1_d[0] <= term1_w[11:0];
            term4_d[0] <= term4_w[11:0];
            term5_d[0] <= term5_w[11:0];
            
            for (i_term = 1; i_term < 4; i_term = i_term + 1) begin
                term1_d[i_term] <= term1_d[i_term-1];
                term4_d[i_term] <= term4_d[i_term-1];
                term5_d[i_term] <= term5_d[i_term-1];
            end
        end
    end

    // =========================================================
    // STAGE 3: MODULAR ADDITION (Latency: 1 cycle)
    // =========================================================
    wire [12:0] sum0 = term1_d[3] + term3_w[11:0];
    wire [12:0] sum1 = term4_d[3] + term5_d[3];

    always @(posedge clk) begin
        if (!rst_n) begin
            c0_out <= 16'd0;
            c1_out <= 16'd0;
        end else if (en) begin
            // c0_out = (term1 + term3) mod Q
            if (sum0 >= KYBER_Q) 
                c0_out <= {4'd0, sum0 - KYBER_Q};
            else                 
                c0_out <= {4'd0, sum0[11:0]};
            
            // c1_out = (term4 + term5) mod Q
            if (sum1 >= KYBER_Q) 
                c1_out <= {4'd0, sum1 - KYBER_Q};
            else                 
                c1_out <= {4'd0, sum1[11:0]};
        end
    end

endmodule
