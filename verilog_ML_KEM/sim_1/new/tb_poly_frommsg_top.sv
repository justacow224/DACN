`timescale 1ns / 1ps

module tb_poly_frommsg_top();

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
    poly_frommsg_top dut (
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
    logic [63:0] buf_mem [0:3];           // 4 words x 8 bytes = 32 bytes
    logic [7:0]  byte_array [0:31];
    logic [15:0] expected_coeffs [0:255]; 

    always @(posedge clk) begin
        buf_dout <= buf_mem[buf_addr]; // 1 cycle latency
    end

    integer valid_coeff_written = 0;

    always @(posedge clk) begin
        if (rst_n && is_running) begin
            if (ram_we_a0) begin
                valid_coeff_written++;
                if (ram_a0_din !== expected_coeffs[ram_addr * 2]) begin
                    $display("   [FATAL ERROR] A0 Mismatch! Addr: %0d, Expected: %0d, Got: %0d", ram_addr, expected_coeffs[ram_addr * 2], ram_a0_din);
                    $finish;
                end
            end
            
            if (ram_we_a1) begin
                valid_coeff_written++;
                if (ram_a1_din !== expected_coeffs[ram_addr * 2 + 1]) begin
                    $display("   [FATAL ERROR] A1 Mismatch! Addr: %0d, Expected: %0d, Got: %0d", ram_addr, expected_coeffs[ram_addr * 2 + 1], ram_a1_din);
                    $finish;
                end
            end
        end
    end

    // =========================================================
    // 5. TEST SEQUENCE
    // =========================================================
    integer tc, i, j;
    logic bit_val;

    initial begin
        clk = 0; rst_n = 0; start = 0;

        $display("=================================================");
        $display("   STARTING BATCH TEST: POLY FROM MSG (d=1)      ");
        $display("=================================================");

        #20; rst_n = 1; #10;

        for (tc = 1; tc <= 5; tc++) begin
            $display("-------------------------------------------------");
            $display(">> RUNNING TESTCASE %0d / 5", tc);
            valid_coeff_written = 0;

            // 1. Generate 32 bytes & Compute Golden Model
            for (i = 0; i < 32; i++) begin
                byte_array[i] = $urandom_range(0, 255);
                for (j = 0; j < 8; j++) begin
                    bit_val = (byte_array[i] >> j) & 1;
                    expected_coeffs[i*8 + j] = bit_val ? 1665 : 0;
                end
            end

            for (i = 0; i < 4; i++) begin
                for (j = 0; j < 8; j++) begin
                    buf_mem[i][j*8 +: 8] = byte_array[i*8 + j];
                end
            end

            // 2. Trigger
            @(posedge clk); start = 1;
            @(posedge clk); start = 0;

            wait(done); @(posedge clk);

            if (valid_coeff_written == 256) begin
                $display("   [SUCCESS] 256 coeffs decoded perfectly.");
                $display("   [PERFORMANCE] Cycles: %0d", cycle_count);
            end else begin
                $display("   [ERROR] Expected 256 coeffs, got %0d", valid_coeff_written); $finish;
            end
        end
        $display("=================================================");
        #50; $finish;
    end
endmodule