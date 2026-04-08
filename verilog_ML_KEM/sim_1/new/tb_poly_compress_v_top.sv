`timescale 1ns / 1ps

module tb_poly_compress_v_top();

    // =========================================================
    // 1. SIGNAL DECLARATIONS
    // =========================================================
    logic         clk;
    logic         rst_n;
    logic         start;
    logic         done;

    logic [6:0]   ram_addr;
    logic [15:0]  ram_a0_dout;
    logic [15:0]  ram_a1_dout;

    logic         buf_we;
    logic [5:0]   buf_addr;
    logic [63:0]  buf_din;

    // =========================================================
    // 2. DEVICE UNDER TEST (DUT)
    // =========================================================
    poly_compress_v_top dut (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .done(done),
        .ram_addr(ram_addr),
        .ram_a0_dout(ram_a0_dout),
        .ram_a1_dout(ram_a1_dout),
        .buf_we(buf_we),
        .buf_addr(buf_addr),
        .buf_din(buf_din)
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
    // 4. MOCK RAM & GOLDEN MODEL
    // =========================================================
    logic signed [15:0] ram_bank0 [0:127];
    logic signed [15:0] ram_bank1 [0:127];
    logic [63:0]        mock_buffer [0:15];     // 16 words x 8 bytes = 128 bytes
    logic [7:0]         expected_bytes [0:127];

    always @(posedge clk) begin
        ram_a0_dout <= ram_bank0[ram_addr];
        ram_a1_dout <= ram_bank1[ram_addr];
    end

    always @(posedge clk) begin
        if (buf_we) mock_buffer[buf_addr] <= buf_din;
    end

    // =========================================================
    // 5. TEST SEQUENCE
    // =========================================================
    integer tc, i, j;
    integer errors;
    logic [7:0] extracted_byte;
    
    // Biến cho Golden Model
    integer val0, val1;
    longint t0, t1;
    logic [3:0] u0, u1;

    initial begin
        clk = 0; rst_n = 0; start = 0;

        $display("=================================================");
        $display("     STARTING BATCH TEST: POLY COMPRESS (V)      ");
        $display("=================================================");

        #20; rst_n = 1; #10;

        for (tc = 1; tc <= 5; tc++) begin
            $display("-------------------------------------------------");
            $display(">> RUNNING TESTCASE %0d / 5", tc);
            
            // 1. Generate 256 random coeffs & Calculate Golden Model
            for (i = 0; i < 128; i++) begin
                // Tạo số ngẫu nhiên dải [-3329, 3329]
                val0 = $urandom_range(0, 6658) - 3329; 
                val1 = $urandom_range(0, 6658) - 3329; 
                
                ram_bank0[i] = val0;
                ram_bank1[i] = val1;

                // Chuẩn hóa toán học (C++ Logic)
                while (val0 < 0) val0 += 3329;
                while (val0 >= 3329) val0 -= 3329;
                while (val1 < 0) val1 += 3329;
                while (val1 >= 3329) val1 -= 3329;
                
                // d=4 -> mul 16
                t0 = val0 * 16 + 1664;
                t1 = val1 * 16 + 1664;
                
                u0 = (t0 / 3329) & 4'hF;
                u1 = (t1 / 3329) & 4'hF;
                
                // Ghép 2 hệ số 4-bit thành 1 byte
                expected_bytes[i] = {u1, u0};
            end

            // 2. Trigger DUT
            @(posedge clk);
            start = 1;
            @(posedge clk);
            start = 0;

            // 3. Chờ phần cứng chạy xong
            wait(done);
            @(posedge clk);

            // 4. Kiểm tra đối chiếu
            errors = 0;
            for (i = 0; i < 16; i++) begin
                for (j = 0; j < 8; j++) begin
                    extracted_byte = mock_buffer[i][j*8 +: 8];
                    if (extracted_byte !== expected_bytes[i*8 + j]) begin
                        $display("   [ERROR] Byte %0d mismatch. Expected: %02x, Got: %02x", i*8 + j, expected_bytes[i*8 + j], extracted_byte);
                        errors++;
                    end
                end
            end

            if (errors == 0) begin
                $display("   [SUCCESS] Exactly 128 valid bytes compressed & verified.");
                $display("   [PERFORMANCE] Completed in %0d clock cycles.", cycle_count);
            end else begin
                $display("   [FAILED] Testcase had %0d errors.", errors);
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