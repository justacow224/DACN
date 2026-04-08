`timescale 1ns / 1ps

module tb_poly_to_bytes_top();

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
    poly_to_bytes_top dut (
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
    logic [15:0] ram_bank0 [0:127];
    logic [15:0] ram_bank1 [0:127];
    logic [63:0] mock_buffer [0:47];
    logic [7:0]  expected_bytes [0:383];

    // BRAM Read Latency Simulation (1 cycle delay)
    always @(posedge clk) begin
        ram_a0_dout <= ram_bank0[ram_addr];
        ram_a1_dout <= ram_bank1[ram_addr];
    end

    // MOCK Buffer Write
    always @(posedge clk) begin
        if (buf_we) begin
            mock_buffer[buf_addr] <= buf_din;
        end
    end

    // =========================================================
    // 5. TEST SEQUENCE
    // =========================================================
    integer tc, i, j;
    logic [11:0] c0, c1;
    integer errors;
    logic [7:0] extracted_byte;

    initial begin
        clk = 0; rst_n = 0; start = 0;

        $display("=================================================");
        $display("   STARTING BATCH TEST: POLY TO BYTES (ENCODE)   ");
        $display("=================================================");

        #20; rst_n = 1; #10;

        for (tc = 1; tc <= 5; tc++) begin
            $display("-------------------------------------------------");
            $display(">> RUNNING TESTCASE %0d / 5", tc);
            
            // 1. Generate 256 random 12-bit coefficients & Calculate Golden Model
            for (i = 0; i < 128; i++) begin
                c0 = $urandom_range(0, 3328);
                c1 = $urandom_range(0, 3328);
                
                ram_bank0[i] = {4'd0, c0};
                ram_bank1[i] = {4'd0, c1};
                
                expected_bytes[3*i]     = c0[7:0];
                expected_bytes[3*i + 1] = {c1[3:0], c0[11:8]};
                expected_bytes[3*i + 2] = c1[11:4];
            end

            // 2. Trigger DUT
            @(posedge clk);
            start = 1;
            @(posedge clk);
            start = 0;

            // 3. Wait for Completion
            wait(done);
            @(posedge clk);

            // 4. Verify output Buffer against Golden Model
            errors = 0;
            for (i = 0; i < 48; i++) begin
                for (j = 0; j < 8; j++) begin
                    extracted_byte = mock_buffer[i][j*8 +: 8];
                    if (extracted_byte !== expected_bytes[i*8 + j]) begin
                        $display("   [ERROR] Byte %0d mismatch. Expected: %02x, Got: %02x", i*8 + j, expected_bytes[i*8 + j], extracted_byte);
                        errors++;
                    end
                end
            end

            if (errors == 0) begin
                $display("   [SUCCESS] Exactly 384 valid bytes encoded & verified.");
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