`timescale 1ns / 1ps

module tb_keccak_sponge_top();

    // =========================================================
    // 1. SIGNAL DECLARATIONS
    // =========================================================
    logic         clk;
    logic         rst_n;
    logic         init;
    logic [1:0]   hash_type;
    logic         finalize;
    logic [7:0]   din;
    logic         din_valid;
    logic         din_ready;
    logic [7:0]   dout;
    logic         dout_valid;
    logic         dout_ready;

    // =========================================================
    // 2. DEVICE UNDER TEST (DUT)
    // =========================================================
    keccak_sponge_top dut (
        .clk(clk), .rst_n(rst_n), .init(init), .hash_type(hash_type), .finalize(finalize),
        .din(din), .din_valid(din_valid), .din_ready(din_ready),
        .dout(dout), .dout_valid(dout_valid), .dout_ready(dout_ready)
    );

    // =========================================================
    // 3. CLOCK GENERATION & PERFORMANCE COUNTER
    // =========================================================
    always #5 clk = ~clk;

    integer cycle_count;
    logic   is_running;

    always @(posedge clk) begin
        if (!rst_n) begin
            cycle_count <= 0;
        end else if (is_running) begin
            cycle_count <= cycle_count + 1;
        end
    end

    // =========================================================
    // 4. NIST KNOWN ANSWER TESTS (KATs)
    // =========================================================
    logic [7:0] input_msg [0:2] = '{8'h61, 8'h62, 8'h63}; // "abc"

    logic [7:0] exp_shake128 [0:31] = '{
        8'h58, 8'h81, 8'h09, 8'h2d, 8'hd8, 8'h18, 8'hbf, 8'h5c, 8'hf8, 8'ha3, 8'hdd, 8'hb7, 8'h93, 8'hfb, 8'hcb, 8'ha7, 
        8'h40, 8'h97, 8'hd5, 8'hc5, 8'h26, 8'ha6, 8'hd3, 8'h5f, 8'h97, 8'hb8, 8'h33, 8'h51, 8'h94, 8'h0f, 8'h2c, 8'hc8
    };

    logic [7:0] exp_shake256 [0:31] = '{
        8'h48, 8'h33, 8'h66, 8'h60, 8'h13, 8'h60, 8'ha8, 8'h77, 8'h1c, 8'h68, 8'h63, 8'h08, 8'h0c, 8'hc4, 8'h11, 8'h4d, 
        8'h8d, 8'hb4, 8'h45, 8'h30, 8'hf8, 8'hf1, 8'he1, 8'hee, 8'h4f, 8'h94, 8'hea, 8'h37, 8'he7, 8'h8b, 8'h57, 8'h39
    };

    logic [7:0] exp_sha3_256 [0:31] = '{
        8'h3a, 8'h98, 8'h5d, 8'ha7, 8'h4f, 8'he2, 8'h25, 8'hb2, 8'h04, 8'h5c, 8'h17, 8'h2d, 8'h6b, 8'hd3, 8'h90, 8'hbd,
        8'h85, 8'h5f, 8'h08, 8'h6e, 8'h3e, 8'h9d, 8'h52, 8'h5b, 8'h46, 8'hbf, 8'he2, 8'h45, 8'h11, 8'h43, 8'h15, 8'h32
    };

    logic [7:0] exp_sha3_512 [0:63] = '{
        8'hb7, 8'h51, 8'h85, 8'h0b, 8'h1a, 8'h57, 8'h16, 8'h8a, 8'h56, 8'h93, 8'hcd, 8'h92, 8'h4b, 8'h6b, 8'h09, 8'h6e,
        8'h08, 8'hf6, 8'h21, 8'h82, 8'h74, 8'h44, 8'hf7, 8'h0d, 8'h88, 8'h4f, 8'h5d, 8'h02, 8'h40, 8'hd2, 8'h71, 8'h2e,
        8'h10, 8'he1, 8'h16, 8'he9, 8'h19, 8'h2a, 8'hf3, 8'hc9, 8'h1a, 8'h7e, 8'hc5, 8'h76, 8'h47, 8'he3, 8'h93, 8'h40,
        8'h57, 8'h34, 8'h0b, 8'h4c, 8'hf4, 8'h08, 8'hd5, 8'ha5, 8'h65, 8'h92, 8'hf8, 8'h27, 8'h4e, 8'hec, 8'h53, 8'hf0
    };

    logic [7:0] exp_multi_absorb [0:31] = '{
        8'h0c, 8'h42, 8'h34, 8'hca, 8'h1e, 8'h31, 8'h80, 8'h1a, 8'he6, 8'h06, 8'hf8, 8'hb8, 8'hd8, 8'he0, 8'h66, 8'h5c, 
        8'h66, 8'hf4, 8'h2a, 8'h21, 8'hd6, 8'h01, 8'hc2, 8'h68, 8'h18, 8'h58, 8'ha9, 8'h2c, 8'h79, 8'had, 8'h5d, 8'h69
    };

    logic [7:0] exp_multi_squeeze [0:199] = '{
        8'h58, 8'h81, 8'h09, 8'h2d, 8'hd8, 8'h18, 8'hbf, 8'h5c, 8'hf8, 8'ha3, 8'hdd, 8'hb7, 8'h93, 8'hfb, 8'hcb, 8'ha7,
        8'h40, 8'h97, 8'hd5, 8'hc5, 8'h26, 8'ha6, 8'hd3, 8'h5f, 8'h97, 8'hb8, 8'h33, 8'h51, 8'h94, 8'h0f, 8'h2c, 8'hc8,
        8'h44, 8'hc5, 8'h0a, 8'hf3, 8'h2a, 8'hcd, 8'h3f, 8'h2c, 8'hdd, 8'h06, 8'h65, 8'h68, 8'h70, 8'h6f, 8'h50, 8'h9b,
        8'hc1, 8'hbd, 8'hde, 8'h58, 8'h29, 8'h5d, 8'hae, 8'h3f, 8'h89, 8'h1a, 8'h9a, 8'h0f, 8'hca, 8'h57, 8'h83, 8'h78,
        8'h9a, 8'h41, 8'hf8, 8'h61, 8'h12, 8'h14, 8'hce, 8'h61, 8'h23, 8'h94, 8'hdf, 8'h28, 8'h6a, 8'h62, 8'hd1, 8'ha2,
        8'h25, 8'h2a, 8'ha9, 8'h4d, 8'hb9, 8'hc5, 8'h38, 8'h95, 8'h6c, 8'h71, 8'h7d, 8'hc2, 8'hbe, 8'hd4, 8'hf2, 8'h32,
        8'ha0, 8'h29, 8'h4c, 8'h85, 8'h7c, 8'h73, 8'h0a, 8'ha1, 8'h60, 8'h67, 8'hac, 8'h10, 8'h62, 8'hf1, 8'h20, 8'h1f,
        8'hb0, 8'hd3, 8'h77, 8'hcf, 8'hb9, 8'hcd, 8'he4, 8'hc6, 8'h35, 8'h99, 8'hb2, 8'h7f, 8'h34, 8'h62, 8'hbb, 8'ha4,
        8'ha0, 8'hed, 8'h29, 8'h6c, 8'h80, 8'h1f, 8'h9f, 8'hf7, 8'hf5, 8'h73, 8'h02, 8'hbb, 8'h30, 8'h76, 8'hee, 8'h14,
        8'h5f, 8'h97, 8'ha3, 8'h2a, 8'he6, 8'h8e, 8'h76, 8'hab, 8'h66, 8'hc4, 8'h8d, 8'h51, 8'h67, 8'h5b, 8'hd4, 8'h9a,
        8'hcc, 8'h29, 8'h08, 8'h2f, 8'h56, 8'h47, 8'h58, 8'h4e, 8'h6a, 8'ha0, 8'h1b, 8'h3f, 8'h5a, 8'hf0, 8'h57, 8'h80,
        8'h5f, 8'h97, 8'h3f, 8'hf8, 8'hec, 8'hb8, 8'hb2, 8'h26, 8'hac, 8'h32, 8'had, 8'ha6, 8'hf0, 8'h1c, 8'h1f, 8'hcd,
        8'h48, 8'h18, 8'hcb, 8'h00, 8'h6a, 8'ha5, 8'hb4, 8'hcd
    };

    // =========================================================
    // 5. HELPER TASKS
    // =========================================================
    task automatic feed_message();
        integer i;
        for (i = 0; i < 3; i = i + 1) begin
            din = input_msg[i];
            din_valid = 1;
            do begin
                @(posedge clk);
            end while (!din_ready);
        end
        din_valid = 0;
        @(posedge clk);
    endtask

    task automatic feed_message_200();
        integer i;
        for (i = 0; i < 200; i = i + 1) begin
            din = i[7:0]; // 0, 1, 2, ..., 199
            din_valid = 1;
            do begin
                @(posedge clk);
            end while (!din_ready);
        end
        din_valid = 0;
        @(posedge clk);
    endtask

    integer i, errors;

    initial begin
        clk = 0; rst_n = 0; init = 0; hash_type = 0; finalize = 0; din = 0; 
        din_valid = 0; dout_ready = 1; is_running = 0; cycle_count = 0;

        $display("=================================================");
        $display("   STARTING BATCH TEST: KECCAK SPONGE (4 MODES)  ");
        $display("=================================================");

        #20; rst_n = 1; #10;

        // --- SHAKE128 ---
        $display(">> RUNNING TESTCASE 1: SHAKE128");
        @(posedge clk); init = 1; hash_type = 2'b00; is_running = 1; cycle_count = 0;
        @(posedge clk); init = 0;
        feed_message();
        finalize = 1; @(posedge clk); finalize = 0;

        errors = 0;
        for (i = 0; i < 32; i = i + 1) begin
            do begin @(posedge clk); end while (!dout_valid);
            if (dout !== exp_shake128[i]) begin
                $display("   [ERROR] Byte %0d: Expected %02x, Got %02x", i, exp_shake128[i], dout);
                errors = errors + 1;
            end
        end
        is_running = 0;
        $display("   [PERFORMANCE] SHAKE128 generated 32 bytes in %0d clock cycles.", cycle_count);
        if (errors == 0) $display(">> [SUCCESS] SHAKE128 PASSED!");
        else $finish;

        // --- SHAKE256 ---
        $display("-------------------------------------------------");
        $display(">> RUNNING TESTCASE 2: SHAKE256");
        @(posedge clk); init = 1; hash_type = 2'b01; is_running = 1; cycle_count = 0;
        @(posedge clk); init = 0;
        feed_message();
        finalize = 1; @(posedge clk); finalize = 0;

        errors = 0;
        for (i = 0; i < 32; i = i + 1) begin
            do begin @(posedge clk); end while (!dout_valid);
            if (dout !== exp_shake256[i]) begin
                $display("   [ERROR] Byte %0d: Expected %02x, Got %02x", i, exp_shake256[i], dout);
                errors = errors + 1;
            end
        end
        is_running = 0;
        $display("   [PERFORMANCE] SHAKE256 generated 32 bytes in %0d clock cycles.", cycle_count);
        if (errors == 0) $display(">> [SUCCESS] SHAKE256 PASSED!");
        else $finish;

        // --- SHA3-256 ---
        $display("-------------------------------------------------");
        $display(">> RUNNING TESTCASE 3: SHA3-256");
        @(posedge clk); init = 1; hash_type = 2'b10; is_running = 1; cycle_count = 0;
        @(posedge clk); init = 0;
        feed_message();
        finalize = 1; @(posedge clk); finalize = 0;

        errors = 0;
        for (i = 0; i < 32; i = i + 1) begin
            do begin @(posedge clk); end while (!dout_valid);
            if (dout !== exp_sha3_256[i]) begin
                $display("   [ERROR] Byte %0d: Expected %02x, Got %02x", i, exp_sha3_256[i], dout);
                errors = errors + 1;
            end
        end
        is_running = 0;
        $display("   [PERFORMANCE] SHA3-256 generated 32 bytes in %0d clock cycles.", cycle_count);
        if (errors == 0) $display(">> [SUCCESS] SHA3-256 PASSED!");
        else $finish;

        // --- SHA3-512 ---
        $display("-------------------------------------------------");
        $display(">> RUNNING TESTCASE 4: SHA3-512");
        @(posedge clk); init = 1; hash_type = 2'b11; is_running = 1; cycle_count = 0;
        @(posedge clk); init = 0;
        feed_message();
        finalize = 1; @(posedge clk); finalize = 0;

        errors = 0;
        for (i = 0; i < 64; i = i + 1) begin
            do begin @(posedge clk); end while (!dout_valid);
            if (dout !== exp_sha3_512[i]) begin
                $display("   [ERROR] Byte %0d: Expected %02x, Got %02x", i, exp_sha3_512[i], dout);
                errors = errors + 1;
            end
        end
        is_running = 0;
        $display("   [PERFORMANCE] SHA3-512 generated 64 bytes in %0d clock cycles.", cycle_count);
        if (errors == 0) $display(">> [SUCCESS] SHA3-512 PASSED!");
        else $finish;

        // --- MULTI-BLOCK ABSORB ---
        $display("-------------------------------------------------");
        $display(">> RUNNING TESTCASE 5: MULTI-BLOCK ABSORB (SHAKE128)");
        @(posedge clk); init = 1; hash_type = 2'b00; is_running = 1; cycle_count = 0;
        @(posedge clk); init = 0;
        feed_message_200();
        finalize = 1; @(posedge clk); finalize = 0;

        errors = 0;
        for (i = 0; i < 32; i = i + 1) begin
            do begin @(posedge clk); end while (!dout_valid);
            if (dout !== exp_multi_absorb[i]) begin
                $display("   [ERROR] Byte %0d: Expected %02x, Got %02x", i, exp_multi_absorb[i], dout);
                errors = errors + 1;
            end
        end
        is_running = 0;
        $display("   [PERFORMANCE] MULTI-BLOCK ABSORB generated 32 bytes in %0d clock cycles.", cycle_count);
        if (errors == 0) $display(">> [SUCCESS] MULTI-BLOCK ABSORB PASSED!");
        else $finish;

        // --- MULTI-BLOCK SQUEEZE ---
        $display("-------------------------------------------------");
        $display(">> RUNNING TESTCASE 6: MULTI-BLOCK SQUEEZE (SHAKE128)");
        @(posedge clk); init = 1; hash_type = 2'b00; is_running = 1; cycle_count = 0;
        @(posedge clk); init = 0;
        feed_message();
        finalize = 1; @(posedge clk); finalize = 0;

        errors = 0;
        for (i = 0; i < 200; i = i + 1) begin
            do begin @(posedge clk); end while (!dout_valid);
            if (dout !== exp_multi_squeeze[i]) begin
                $display("   [ERROR] Byte %0d: Expected %02x, Got %02x", i, exp_multi_squeeze[i], dout);
                errors = errors + 1;
            end
        end
        is_running = 0;
        $display("   [PERFORMANCE] MULTI-BLOCK SQUEEZE generated 200 bytes in %0d clock cycles.", cycle_count);
        if (errors == 0) $display(">> [SUCCESS] MULTI-BLOCK SQUEEZE PASSED!");
        else $finish;

        $display("=================================================");
        $display("   ALL 6 TESTCASES PASSED FLAWLESSLY! CONGRATS!  ");
        $display("=================================================");
        #50; $finish;
    end

endmodule