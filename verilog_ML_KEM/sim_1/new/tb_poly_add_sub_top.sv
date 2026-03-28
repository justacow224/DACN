`timescale 1ns / 1ps

module tb_poly_add_sub_top();

    // =========================================================
    // 1. SIGNAL DECLARATIONS
    // =========================================================
    logic         clk;
    logic         rst_n;
    logic         start;
    logic         is_sub;
    logic         done;

    logic         host_sel;
    logic         host_we;
    logic [7:0]   host_addr;
    logic [15:0]  host_din;
    logic [15:0]  host_dout;

    // =========================================================
    // 2. DEVICE UNDER TEST (DUT)
    // =========================================================
    poly_add_sub_top dut (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .is_sub(is_sub),
        .done(done),
        .host_sel(host_sel),
        .host_we(host_we),
        .host_addr(host_addr),
        .host_din(host_din),
        .host_dout(host_dout)
    );

    // =========================================================
    // 3. CLOCK & PERFORMANCE COUNTER
    // =========================================================
    always #5 clk = ~clk;

    integer cycle_count;
    logic   is_running;

    always @(posedge clk) begin
        if (!rst_n) begin
            cycle_count <= 0;
            is_running  <= 0;
        end else begin
            if (start) begin
                cycle_count <= 0;
                is_running  <= 1;
            end else if (done) begin
                is_running  <= 0;
            end else if (is_running) begin
                cycle_count <= cycle_count + 1;
            end
        end
    end

    // =========================================================
    // 4. TEST VECTORS (AUTO-GENERATED)
    // =========================================================
    logic [15:0] INPUT_A [0:255];
    logic [15:0] INPUT_B [0:255];
    logic [15:0] EXPECTED_ADD [0:255];
    logic [15:0] EXPECTED_SUB [0:255];

    integer i;
    integer errors;

    initial begin
        // Generate deterministic inputs and expected outputs
        for (i = 0; i < 256; i = i + 1) begin
            INPUT_A[i] = (i * 123) % 3329; // Pseudo-random generation
            INPUT_B[i] = (i * 321) % 3329;
            
            // Calculate Math
            EXPECTED_ADD[i] = (INPUT_A[i] + INPUT_B[i]) % 3329;
            
            if (INPUT_A[i] >= INPUT_B[i])
                EXPECTED_SUB[i] = INPUT_A[i] - INPUT_B[i];
            else
                EXPECTED_SUB[i] = INPUT_A[i] + 3329 - INPUT_B[i];
        end

        // Initialize
        clk       = 0;
        rst_n     = 0;
        start     = 0;
        is_sub    = 0;
        host_sel  = 0;
        host_we   = 0;
        host_addr = 0;
        host_din  = 0;

        $display("=================================================");
        $display("     STARTING TEST: POLY ADD / SUB MODULE        ");
        $display("=================================================");

        #20;
        rst_n = 1;
        #10;

        // ---------------------------------------------------------
        // TESTCASE 1: POLY ADDITION
        // ---------------------------------------------------------
        $display(">> RUNNING TESTCASE 1: POLY ADDITION");
        
        // Load Polynomial A into RAM A (host_sel = 0)
        host_sel = 0;
        for (i = 0; i < 256; i = i + 1) begin
            @(negedge clk);
            host_we   = 1;
            host_addr = i;
            host_din  = INPUT_A[i];
        end
        @(negedge clk); // Safe flush
        
        // Load Polynomial B into RAM B (host_sel = 1)
        host_sel = 1;
        for (i = 0; i < 256; i = i + 1) begin
            @(negedge clk);
            host_we   = 1;
            host_addr = i;
            host_din  = INPUT_B[i];
        end
        @(negedge clk); host_we = 0;

        // Start ADD operation
        @(negedge clk);
        is_sub = 0;
        start  = 1;
        @(negedge clk);
        start  = 0;

        wait(done);
        @(negedge clk);
        $display("   [PERFORMANCE] Addition took %0d clock cycles.", cycle_count);

        // Verify ADD Results
        errors = 0;
        host_sel = 0; // Read from RAM A
        for (i = 0; i < 256; i = i + 1) begin
            host_addr = i;
            @(posedge clk);
            @(negedge clk);
            if (host_dout !== EXPECTED_ADD[i]) begin
                $display("   [ERROR] ADD mismatch at index %0d: Expected %0d, Got %0d", i, EXPECTED_ADD[i], host_dout);
                errors = errors + 1;
            end
        end
        if (errors == 0) $display(">> [SUCCESS] POLY ADDITION PASSED 100%%!");


        // ---------------------------------------------------------
        // TESTCASE 2: POLY SUBTRACTION
        // ---------------------------------------------------------
        $display("-------------------------------------------------");
        $display(">> RUNNING TESTCASE 2: POLY SUBTRACTION");
        
        // Reload Polynomial A into RAM A (since it was overwritten by ADD)
        host_sel = 0;
        for (i = 0; i < 256; i = i + 1) begin
            @(negedge clk);
            host_we   = 1;
            host_addr = i;
            host_din  = INPUT_A[i];
        end
        @(negedge clk); host_we = 0;
        // RAM B still holds Polynomial B, no need to reload!

        // Start SUB operation
        @(negedge clk);
        is_sub = 1; // FLIP THE SWITCH TO SUBTRACTION!
        start  = 1;
        @(negedge clk);
        start  = 0;

        wait(done);
        @(negedge clk);
        $display("   [PERFORMANCE] Subtraction took %0d clock cycles.", cycle_count);

        // Verify SUB Results
        errors = 0;
        host_sel = 0; // Read from RAM A
        for (i = 0; i < 256; i = i + 1) begin
            host_addr = i;
            @(posedge clk);
            @(negedge clk);
            if (host_dout !== EXPECTED_SUB[i]) begin
                $display("   [ERROR] SUB mismatch at index %0d: Expected %0d, Got %0d", i, EXPECTED_SUB[i], host_dout);
                errors = errors + 1;
            end
        end
        if (errors == 0) $display(">> [SUCCESS] POLY SUBTRACTION PASSED 100%%!");

        $display("=================================================");
        $display("   ALL TESTCASES PASSED FLAWLESSLY! CONGRATS!    ");
        $display("=================================================");
        
        #50;
        $finish;
    end

endmodule