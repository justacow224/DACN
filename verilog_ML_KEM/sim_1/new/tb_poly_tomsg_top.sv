`timescale 1ns / 1ps

module tb_poly_tomsg_top();

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
    // 2. DEVICE UNDER TEST
    // =========================================================
    poly_tomsg_top dut (
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

    always #5 clk = ~clk;

    integer cycle_count;
    logic   is_running;
    always @(posedge clk) begin
        if (!rst_n) begin cycle_count <= 0; is_running <= 0; end
        else if (start) begin cycle_count <= 0; is_running <= 1; end
        else if (done) is_running <= 0;
        else if (is_running) cycle_count <= cycle_count + 1;
    end

    // =========================================================
    // 3. MOCK RAM & GOLDEN MODEL
    // =========================================================
    logic signed [15:0] ram_bank0 [0:127];
    logic signed [15:0] ram_bank1 [0:127];
    logic [63:0]        mock_buffer [0:3];
    logic [7:0]         expected_bytes [0:31];

    always @(posedge clk) begin
        ram_a0_dout <= ram_bank0[ram_addr];
        ram_a1_dout <= ram_bank1[ram_addr];
        if (buf_we) mock_buffer[buf_addr] <= buf_din;
    end

    // =========================================================
    // 4. TEST SEQUENCE
    // =========================================================
    integer tc, i, j;
    integer val0, val1;
    integer bit0, bit1;
    integer errors;
    logic [7:0] ext_byte;

    initial begin
        clk = 0; rst_n = 0; start = 0;

        $display("=================================================");
        $display("   STARTING BATCH TEST: POLY TO MSG (d=1)        ");
        $display("=================================================");

        #20; rst_n = 1; #10;

        for (tc = 1; tc <= 5; tc++) begin
            $display("-------------------------------------------------");
            $display(">> RUNNING TESTCASE %0d / 5", tc);
            
            for (i = 0; i < 32; i++) expected_bytes[i] = 0;

            for (i = 0; i < 128; i++) begin
                val0 = $urandom_range(0, 6658) - 3329;
                val1 = $urandom_range(0, 6658) - 3329;
                
                ram_bank0[i] = val0;
                ram_bank1[i] = val1;

                while (val0 < 0) val0 += 3329; while (val0 >= 3329) val0 -= 3329;
                while (val1 < 0) val1 += 3329; while (val1 >= 3329) val1 -= 3329;

                bit0 = (val0 >= 833 && val0 <= 2496) ? 1 : 0;
                bit1 = (val1 >= 833 && val1 <= 2496) ? 1 : 0;

                // Packing bits into expected_bytes
                expected_bytes[(2*i) / 8]   |= (bit0 << ((2*i) % 8));
                expected_bytes[(2*i+1) / 8] |= (bit1 << ((2*i+1) % 8));
            end

            @(posedge clk); start = 1;
            @(posedge clk); start = 0;
            wait(done); @(posedge clk);

            errors = 0;
            for (i = 0; i < 4; i++) begin
                for (j = 0; j < 8; j++) begin
                    ext_byte = mock_buffer[i][j*8 +: 8];
                    if (ext_byte !== expected_bytes[i*8 + j]) begin
                        $display("   [ERROR] Byte %0d mismatch. Exp: %02x, Got: %02x", i*8+j, expected_bytes[i*8+j], ext_byte);
                        errors++;
                    end
                end
            end

            if (errors == 0) begin
                $display("   [SUCCESS] 32 bytes encoded perfectly.");
                $display("   [PERFORMANCE] Cycles: %0d", cycle_count);
            end else $finish;
        end
        $display("=================================================");
        #50; $finish;
    end
endmodule