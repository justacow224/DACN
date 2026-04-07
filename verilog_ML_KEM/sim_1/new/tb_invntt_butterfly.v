`timescale 1ns / 1ps

module tb_invntt_butterfly();

    // =========================================================
    // 1. SIGNAL DECLARATIONS
    // =========================================================
    reg         clk;
    reg         rst_n;
    reg         en;
    
    reg  [15:0] a;
    reg  [15:0] b;
    reg  [15:0] inv_zeta;
    
    wire [15:0] a_prime;
    wire [15:0] b_prime;

    // =========================================================
    // 2. DEVICE UNDER TEST (DUT)
    // =========================================================
    invntt_butterfly dut (
        .clk(clk),
        .rst_n(rst_n),
        .en(en),
        .a(a),
        .b(b),
        .inv_zeta(inv_zeta),
        .a_prime(a_prime),
        .b_prime(b_prime)
    );

    // =========================================================
    // 3. CLOCK GENERATION (10ns period -> 100MHz)
    // =========================================================
    always #5 clk = ~clk;

    // =========================================================
    // 4. STIMULUS PROCESS
    // =========================================================
    integer errors = 0;

    initial begin
        // Initialize inputs
        clk      = 0;
        rst_n    = 0;
        en       = 0;
        a        = 0;
        b        = 0;
        inv_zeta = 0;

        $display("=================================================");
        $display("   STARTING INVERSE BUTTERFLY PIPELINE TEST      ");
        $display("=================================================");

        // Wait 20ns and release reset
        #20;
        rst_n = 1;
        
        // Enable the pipeline
        @(negedge clk);
        en = 1;

        // ---------------------------------------------------------
        // CLOCK 1: Inject Test Vector 1 (Normal Case)
        // GS Math: a' = (1000 + 2000) % 3329 = 3000
        //          b' = ((1000 - 2000) % 3329 * 1729) % 3329 
        //             = (2329 * 1729) % 3329 = 2080
        // ---------------------------------------------------------
        a = 16'd1000; b = 16'd2000; inv_zeta = 16'd1729;
        
        // ---------------------------------------------------------
        // CLOCK 2: Inject Test Vector 2 (Maximum Upper Bound)
        // GS Math: a' = (3328 + 3328) % 3329 = 3327
        //          b' = ((3328 - 3328) % 3329 * 1) % 3329 = 0
        // ---------------------------------------------------------
        @(negedge clk);
        a = 16'd3328; b = 16'd3328; inv_zeta = 16'd1;

        // ---------------------------------------------------------
        // CLOCK 3: Inject Test Vector 3 (Minimum / Underflow Case)
        // GS Math: a' = (0 + 1) % 3329 = 1
        //          b' = ((0 - 1) % 3329 * 1729) % 3329
        //             = (0 - 1 + 3329 * 1729) % 3329
        //             = (3328 * 1729) % 3329 = 1600
        // ---------------------------------------------------------
        @(negedge clk);
        a = 16'd0; b = 16'd1; inv_zeta = 16'd1729;

        // ---------------------------------------------------------
        // CLOCK 4: Stop data injection, wait for results
        // ---------------------------------------------------------
        @(negedge clk);
        a = 0; b = 0; inv_zeta = 0; 
        en = 1; // Keep enable high to flush the pipeline

        // Wait for Test 1 results (Total 5 cycles delay from injection)
        @(negedge clk); // Clock 5
        @(negedge clk); // Clock 6 -> Test 1 output is ready
        $display("[TEST 1] a'= %0d (Expected: 3000) | b'= %0d (Expected: 2080)", a_prime, b_prime);
        if (a_prime !== 16'd3000 || b_prime !== 16'd2080) begin
            $display("   -> [ERROR] Test 1 Failed!");
            errors = errors + 1;
        end

        // Next cycle: Test 2 results
        @(negedge clk); // Clock 7
        $display("[TEST 2] a'= %0d (Expected: 3327) | b'= %0d (Expected: 0)", a_prime, b_prime);
        if (a_prime !== 16'd3327 || b_prime !== 16'd0) begin
            $display("   -> [ERROR] Test 2 Failed!");
            errors = errors + 1;
        end

        // Next cycle: Test 3 results
        @(negedge clk); // Clock 8
        $display("[TEST 3] a'= %0d (Expected: 1)    | b'= %0d (Expected: 1600)", a_prime, b_prime);
        if (a_prime !== 16'd1 || b_prime !== 16'd1600) begin
            $display("   -> [ERROR] Test 3 Failed!");
            errors = errors + 1;
        end

        $display("=================================================");
        if (errors == 0) begin
            $display(">> [SUCCESS] SIMULATION COMPLETED - ALL PASSED! <<");
        end else begin
            $display(">> [FAILED] SIMULATION COMPLETED - %0d ERRORS! <<", errors);
        end
        $display("=================================================");
        
        // End simulation
        #20;
        $finish;
    end

endmodule