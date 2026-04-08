`timescale 1ns / 1ps

module tb_poly_decompress_top();

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
    poly_decompress_top dut (
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
    // 4. MOCK BUFFER & GOLDEN MODEL
    // =========================================================
    logic [63:0] buf_mem [0:39];          // 40 words x 8 bytes = 320 bytes
    logic [7:0]  byte_array [0:319];
    logic [15:0] expected_coeffs [0:255]; 

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
                if (ram_a0_din !== expected_coeffs[ram_addr * 2]) begin
                    $display("   [FATAL ERROR] A0 Mismatch! Addr: %0d, Expected: %0d, Got: %0d", 
                             ram_addr, expected_coeffs[ram_addr * 2], ram_a0_din);
                    $finish;
                end
            end
            
            if (ram_we_a1) begin
                valid_coeff_written++;
                if (ram_a1_din !== expected_coeffs[ram_addr * 2 + 1]) begin
                    $display("   [FATAL ERROR] A1 Mismatch! Addr: %0d, Expected: %0d, Got: %0d", 
                             ram_addr, expected_coeffs[ram_addr * 2 + 1], ram_a1_din);
                    $finish;
                end
            end
        end
    end

    // =========================================================
    // 6. TEST SEQUENCE
    // =========================================================
    integer tc, i, j;
    integer t0, t1, t2, t3, t4;
    integer u0, u1, u2, u3;
    integer v0, v1, v2, v3;

    initial begin
        clk   = 0; rst_n = 0; start = 0;

        $display("=================================================");
        $display("  STARTING BATCH TEST: POLY DECOMPRESS (U)       ");
        $display("=================================================");

        #20; rst_n = 1; #10;

        for (tc = 1; tc <= 5; tc++) begin
            $display("-------------------------------------------------");
            $display(">> RUNNING TESTCASE %0d / 5", tc);
            
            valid_coeff_written = 0;

            // 1. Generate 320 random bytes
            for (i = 0; i < 320; i++) begin
                byte_array[i] = $urandom_range(0, 255);
            end

            // Pack bytes into 64-bit words
            for (i = 0; i < 40; i++) begin
                for (j = 0; j < 8; j++) begin
                    buf_mem[i][j*8 +: 8] = byte_array[i*8 + j];
                end
            end

            // 2. Compute Golden Expected Coefficients (C++ Logic)
            for (i = 0; i < 64; i++) begin
                t0 = byte_array[5*i + 0];
                t1 = byte_array[5*i + 1];
                t2 = byte_array[5*i + 2];
                t3 = byte_array[5*i + 3];
                t4 = byte_array[5*i + 4];

                u0 = t0 | ((t1 & 8'h03) << 8);
                u1 = (t1 >> 2) | ((t2 & 8'h0F) << 6);
                u2 = (t2 >> 4) | ((t3 & 8'h3F) << 4);
                u3 = (t3 >> 6) | (t4 << 2);

                v0 = (u0 * 3329 + 512) >> 10;
                v1 = (u1 * 3329 + 512) >> 10;
                v2 = (u2 * 3329 + 512) >> 10;
                v3 = (u3 * 3329 + 512) >> 10;

                expected_coeffs[4*i + 0] = v0[15:0];
                expected_coeffs[4*i + 1] = v1[15:0];
                expected_coeffs[4*i + 2] = v2[15:0];
                expected_coeffs[4*i + 3] = v3[15:0];
            end

            // 3. Trigger DUT
            @(posedge clk);
            start = 1;
            @(posedge clk);
            start = 0;

            wait(done);
            @(posedge clk);

            // 4. Report
            if (valid_coeff_written == 256) begin
                $display("   [SUCCESS] Exactly 256 valid coefficients decompressed.");
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