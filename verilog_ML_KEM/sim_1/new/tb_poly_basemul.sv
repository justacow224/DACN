`timescale 1ns / 1ps

module tb_poly_basemul();

    // =========================================================
    // 1. SIGNAL DECLARATIONS
    // =========================================================
    logic         clk;
    logic         rst_n;
    logic         en;
    
    logic  [15:0] a0, a1;
    logic  [15:0] b0, b1;
    logic  [15:0] gamma;
    
    logic  [15:0] c0_out, c1_out;

    // =========================================================
    // 2. DEVICE UNDER TEST (DUT)
    // =========================================================
    poly_basemul dut (
        .clk(clk),
        .rst_n(rst_n),
        .en(en),
        .a0(a0),
        .a1(a1),
        .b0(b0),
        .b1(b1),
        .gamma(gamma),
        .c0_out(c0_out),
        .c1_out(c1_out)
    );

    // =========================================================
    // 3. CLOCK GENERATION (10ns period -> 100MHz)
    // =========================================================
    always #5 clk = ~clk;

    // =========================================================
    // 4. PERFORMANCE COUNTER (PIPELINE LATENCY)
    // =========================================================
    integer cycle_count;
    always @(posedge clk) begin
        if (!rst_n) begin
            cycle_count <= 0;
        end else if (en) begin
            cycle_count <= cycle_count + 1;
        end
    end

    // =========================================================
    // 5. STIMULUS PROCESS
    // =========================================================
    initial begin
        // Initialize inputs
        clk   = 0;
        rst_n = 0;
        en    = 0;
        a0 = 0; a1 = 0;
        b0 = 0; b1 = 0;
        gamma = 0;

        $display("=================================================");
        $display("   STARTING BASE MULTIPLICATION PIPELINE TEST    ");
        $display("=================================================");

        // Reset system
        #20;
        rst_n = 1;
        
        // Start Pipeline
        @(negedge clk);
        en = 1;

        // ---------------------------------------------------------
        // CLOCK 1: Inject Test Vector 1 (Normal Case)
        // ---------------------------------------------------------
        a0 = 16'd1000; a1 = 16'd2000; 
        b0 = 16'd500;  b1 = 16'd1500; 
        gamma = 16'd17;
        
        // ---------------------------------------------------------
        // CLOCK 2: Inject Test Vector 2 (Maximum Values)
        // ---------------------------------------------------------
        @(negedge clk);
        a0 = 16'd3328; a1 = 16'd3328; 
        b0 = 16'd3328; b1 = 16'd3328; 
        gamma = 16'd3328;

        // ---------------------------------------------------------
        // CLOCK 3: Inject Test Vector 3 (Small Values & Negative Gamma)
        // ---------------------------------------------------------
        @(negedge clk);
        a0 = 16'd0; a1 = 16'd1; 
        b0 = 16'd2; b1 = 16'd3; 
        gamma = 16'd3312; // -17 mod 3329

        // ---------------------------------------------------------
        // CLOCK 4: Stop data injection, wait for results
        // ---------------------------------------------------------
        @(negedge clk);
        a0 = 0; a1 = 0; 
        b0 = 0; b1 = 0; 
        gamma = 0; 
        
        // Let the pipeline run. We injected at cycle 1, 2, 3.
        // Latency is exactly 9 cycles. 
        // Expecting outputs at cycle 10, 11, 12.
        
        // Wait until cycle_count hits 9
        wait (cycle_count == 9);
        
        // Check Test 1 Result (Cycle 10)
        @(negedge clk); 
        $display("[CYCLE %0d] TEST 1: c0 = %0d (Exp: 370)  | c1 = %0d (Exp: 3250)", cycle_count, c0_out, c1_out);

        // Check Test 2 Result (Cycle 11)
        @(negedge clk); 
        $display("[CYCLE %0d] TEST 2: c0 = %0d (Exp: 0)    | c1 = %0d (Exp: 2)", cycle_count, c0_out, c1_out);

        // Check Test 3 Result (Cycle 12)
        @(negedge clk); 
        $display("[CYCLE %0d] TEST 3: c0 = %0d (Exp: 3278) | c1 = %0d (Exp: 2)", cycle_count, c0_out, c1_out);

        $display("=================================================");
        $display("             SIMULATION COMPLETED                ");
        $display("=================================================");
        
        #20;
        $finish;
    end

endmodule