`timescale 1ns / 1ps

module tb_poly_parse_top();

    // =========================================================
    // 1. SIGNAL DECLARATIONS
    // =========================================================
    logic         clk;
    logic         rst_n;
    logic         start;
    logic         done;

    // Buffer Interface
    logic [6:0]   buf_addr;
    logic [63:0]  buf_dout;

    // RAM Output Interface
    logic         ram_we_a0;
    logic         ram_we_a1;
    logic [6:0]   ram_addr;
    logic [15:0]  ram_a0_din;
    logic [15:0]  ram_a1_din;

    // =========================================================
    // 2. DEVICE UNDER TEST (DUT)
    // =========================================================
    poly_parse_top dut (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .done(done),
        .buf_addr(buf_addr),
        .buf_dout(buf_dout),
        .ram_we_a0(ram_we_a0),
        .ram_we_a1(ram_we_a1),
        .ram_addr(ram_addr),
        .ram_a0_din(ram_a0_din),
        .ram_a1_din(ram_a1_din)
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
    // 4. MOCK SHAKE128 BUFFER (128 words x 64-bit)
    // =========================================================
    logic [63:0] shake_buffer [0:127];

    // Synchronous Read with 1-cycle latency (Standard BRAM behavior)
    always @(posedge clk) begin
        buf_dout <= shake_buffer[buf_addr];
    end

    // =========================================================
    // 5. ON-THE-FLY VERIFICATION & METRICS
    // =========================================================
    integer valid_coeff_written = 0;
    integer rejected_count = 0;

    always @(posedge clk) begin
        if (rst_n && is_running) begin
            if (ram_we_a0) begin
                valid_coeff_written++;
                if (ram_a0_din >= 16'd3329) begin
                    $display("   [FATAL ERROR] Rejection Sampling Failed! A0 wrote %0d (>= 3329)", ram_a0_din);
                    $finish;
                end
            end
            
            if (ram_we_a1) begin
                valid_coeff_written++;
                if (ram_a1_din >= 16'd3329) begin
                    $display("   [FATAL ERROR] Rejection Sampling Failed! A1 wrote %0d (>= 3329)", ram_a1_din);
                    $finish;
                end
            end
        end
    end

    // =========================================================
    // 6. TEST SEQUENCE
    // =========================================================
    integer i, tc;
    
    initial begin
        // Reset signals
        clk   = 0;
        rst_n = 0;
        start = 0;

        $display("=================================================");
        $display("   STARTING BATCH TEST: POLY PARSE (REJECTION)   ");
        $display("=================================================");

        #20;
        rst_n = 1;
        #10;

        // Run 5 random testcases to get an average cycle count
        for (tc = 1; tc <= 5; tc++) begin
            $display("-------------------------------------------------");
            $display(">> RUNNING TESTCASE %0d / 5", tc);
            
            // 1. Fill Mock Buffer with Random Pseudo-SHAKE Data
            for (i = 0; i < 128; i++) begin
                shake_buffer[i] = {$urandom, $urandom};
            end

            // 2. Reset counters
            valid_coeff_written = 0;
            rejected_count = 0;

            // 3. Trigger DUT
            @(posedge clk);
            start = 1;
            @(posedge clk);
            start = 0;

            // 4. Wait for completion
            wait(done);
            @(posedge clk);

            // 5. Reporting
            if (valid_coeff_written == 256) begin
                $display("   [SUCCESS] Exactly 256 valid coefficients written.");
                $display("   [PERFORMANCE] Completed in %0d clock cycles.", cycle_count);
            end else begin
                $display("   [ERROR] Expected 256 coefficients, but wrote %0d.", valid_coeff_written);
            end
        end

        $display("=================================================");
        $display("               SIMULATION COMPLETED              ");
        $display("=================================================");
        #50;
        $finish;
    end

endmodule