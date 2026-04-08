`timescale 1ns / 1ps

module tb_poly_frombytes_top();

    // =========================================================
    // 1. SIGNAL DECLARATIONS
    // =========================================================
    logic         clk;
    logic         rst_n;
    logic         start;
    logic         done;

    logic [5:0]   buf_addr;
    logic [63:0]  buf_dout;

    logic         ram_we_a0;
    logic         ram_we_a1;
    logic [6:0]   ram_addr;
    logic [15:0]  ram_a0_din;
    logic [15:0]  ram_a1_din;

    // =========================================================
    // 2. DEVICE UNDER TEST (DUT)
    // =========================================================
    poly_frombytes_top dut (
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
    // 4. MOCK BUFFER & GOLDEN MODEL (SOFTWARE REFERENCE)
    // =========================================================
    logic [63:0] buf_mem [0:47];          // 48 words x 8 bytes = 384 bytes
    logic [7:0]  byte_array [0:383];      // Nguyên liệu thô 384 bytes
    logic [11:0] expected_coeffs [0:255]; // 256 hệ số 12-bit chuẩn

    // Synchronous Read for Mock Buffer (1 cycle latency)
    always @(posedge clk) begin
        buf_dout <= buf_mem[buf_addr];
    end

    // =========================================================
    // 5. ON-THE-FLY VERIFICATION
    // =========================================================
    integer valid_coeff_written = 0;

    always @(posedge clk) begin
        if (rst_n && is_running) begin
            if (ram_we_a0) begin
                valid_coeff_written++;
                if (ram_a0_din[11:0] !== expected_coeffs[ram_addr * 2]) begin
                    $display("   [FATAL ERROR] A0 Mismatch! Addr: %0d, Expected: %0d, Got: %0d", 
                             ram_addr, expected_coeffs[ram_addr * 2], ram_a0_din[11:0]);
                    $finish;
                end
            end
            
            if (ram_we_a1) begin
                valid_coeff_written++;
                if (ram_a1_din[11:0] !== expected_coeffs[ram_addr * 2 + 1]) begin
                    $display("   [FATAL ERROR] A1 Mismatch! Addr: %0d, Expected: %0d, Got: %0d", 
                             ram_addr, expected_coeffs[ram_addr * 2 + 1], ram_a1_din[11:0]);
                    $finish;
                end
            end
        end
    end

    // =========================================================
    // 6. TEST SEQUENCE
    // =========================================================
    integer tc, i, j;
    logic [7:0] a, b, c;

    initial begin
        clk   = 0; rst_n = 0; start = 0;

        $display("=================================================");
        $display("  STARTING BATCH TEST: POLY FROM BYTES (DECODE)  ");
        $display("=================================================");

        #20; rst_n = 1; #10;

        // Run 5 Random Testcases
        for (tc = 1; tc <= 5; tc++) begin
            $display("-------------------------------------------------");
            $display(">> RUNNING TESTCASE %0d / 5", tc);
            
            valid_coeff_written = 0;

            // 1. Generate 384 random bytes
            for (i = 0; i < 384; i++) begin
                byte_array[i] = $urandom_range(0, 255);
            end

            // 2. Pack bytes into 64-bit words (Little Endian mapping)
            for (i = 0; i < 48; i++) begin
                for (j = 0; j < 8; j++) begin
                    buf_mem[i][j*8 +: 8] = byte_array[i*8 + j];
                end
            end

            // 3. Compute Golden Expected Coefficients
            for (i = 0; i < 128; i++) begin
                a = byte_array[i*3 + 0];
                b = byte_array[i*3 + 1];
                c = byte_array[i*3 + 2];
                
                expected_coeffs[2*i]     = {b[3:0], a};
                expected_coeffs[2*i + 1] = {c, b[7:4]};
            end

            // 4. Trigger DUT
            @(posedge clk);
            start = 1;
            @(posedge clk);
            start = 0;

            // 5. Wait for Completion
            wait(done);
            @(posedge clk);

            // 6. Report
            if (valid_coeff_written == 256) begin
                $display("   [SUCCESS] Exactly 256 valid coefficients decoded & verified.");
                $display("   [PERFORMANCE] Completed in %0d clock cycles.", cycle_count);
            end else begin
                $display("   [ERROR] Expected 256 coefficients, but wrote %0d.", valid_coeff_written);
                $finish;
            end
        end

        $display("=================================================");
        $display("               SIMULATION COMPLETED              ");
        $display("=================================================");
        #50;
        $finish;
    end

endmodule