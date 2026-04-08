`timescale 1ns / 1ps

module tb_poly_compress_top();

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
    poly_compress_top dut (
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
    logic [63:0]        mock_buffer [0:39];
    logic [7:0]         expected_bytes [0:319]; // 320 bytes output

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
    integer tc, i, j, k;
    integer errors;
    logic [7:0] extracted_byte;
    
    // Golden Model Variables
    integer val;
    longint t_val;
    logic [9:0] u [0:3];
    integer base_idx;

    initial begin
        clk = 0; rst_n = 0; start = 0;

        $display("=================================================");
        $display("     STARTING BATCH TEST: POLY COMPRESS (U)      ");
        $display("=================================================");

        #20; rst_n = 1; #10;

        for (tc = 1; tc <= 5; tc++) begin
            $display("-------------------------------------------------");
            $display(">> RUNNING TESTCASE %0d / 5", tc);
            
            // 1. Generate 256 random coeffs (-3329 to 3329) & Calculate Golden
            for (i = 0; i < 64; i++) begin
                // Generate 4 coeffs
                for (k = 0; k < 4; k++) begin
                    val = $urandom_range(0, 6658) - 3329; // Sinh số âm để test bộ Normalize
                    
                    if (k == 0) ram_bank0[i*2]     = val;
                    if (k == 1) ram_bank1[i*2]     = val;
                    if (k == 2) ram_bank0[i*2 + 1] = val;
                    if (k == 3) ram_bank1[i*2 + 1] = val;

                    // Golden C++ Logic
                    while (val < 0) val += 3329;
                    while (val >= 3329) val -= 3329;
                    
                    t_val = val * 1024 + 1664;
                    u[k] = (t_val / 3329) & 10'h3FF;
                end

                // Golden C++ Byte Packing
                base_idx = 5 * i;
                expected_bytes[base_idx + 0] = u[0] & 8'hFF;
                expected_bytes[base_idx + 1] = (u[0] >> 8) | ((u[1] & 8'h3F) << 2);
                expected_bytes[base_idx + 2] = (u[1] >> 6) | ((u[2] & 8'h0F) << 4);
                expected_bytes[base_idx + 3] = (u[2] >> 4) | ((u[3] & 8'h03) << 6);
                expected_bytes[base_idx + 4] = (u[3] >> 2);
            end

            // 2. Trigger DUT
            @(posedge clk);
            start = 1;
            @(posedge clk);
            start = 0;

            wait(done);
            @(posedge clk);

            // 3. Verify
            errors = 0;
            for (i = 0; i < 40; i++) begin
                for (j = 0; j < 8; j++) begin
                    extracted_byte = mock_buffer[i][j*8 +: 8];
                    if (extracted_byte !== expected_bytes[i*8 + j]) begin
                        $display("   [ERROR] Byte %0d mismatch. Expected: %02x, Got: %02x", i*8 + j, expected_bytes[i*8 + j], extracted_byte);
                        errors++;
                    end
                end
            end

            if (errors == 0) begin
                $display("   [SUCCESS] Exactly 320 valid bytes compressed & verified.");
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