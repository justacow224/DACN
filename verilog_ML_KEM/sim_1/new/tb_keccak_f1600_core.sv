`timescale 1ns / 1ps

module tb_keccak_f1600_core();

    // =========================================================
    // 1. SIGNAL DECLARATIONS
    // =========================================================
    logic           clk;
    logic           rst_n;
    logic           start;
    logic [1599:0]  state_in;
    logic [1599:0]  state_out;
    logic           done;

    // Step 3.K1: new ports. TB stays in legacy "load on start" mode
    // (load_on_start=1) so state_in is loaded into A on the start pulse.
    // The byte-XOR/init interface is unused in this TB and tied to 0.
    logic           load_on_start;
    logic           init_pulse;
    logic           xor_we;
    logic [7:0]     xor_byte_addr;
    logic [7:0]     xor_byte_data;
    logic [7:0]     byte_dout;

    // =========================================================
    // 2. DEVICE UNDER TEST (DUT)
    // =========================================================
    keccak_f1600_core dut (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .load_on_start(load_on_start),
        .state_in(state_in),
        .init(init_pulse),
        .xor_we(xor_we),
        .xor_byte_addr(xor_byte_addr),
        .xor_byte_data(xor_byte_data),
        .byte_dout(byte_dout),
        .state_out(state_out),
        .done(done)
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
    // 4. BEHAVIORAL MODEL (GOLDEN REFERENCE)
    // =========================================================
    logic [63:0] RC [0:23];
    initial begin
        RC[0]  = 64'h0000000000000001; RC[1]  = 64'h0000000000008082;
        RC[2]  = 64'h800000000000808A; RC[3]  = 64'h8000000080008000;
        RC[4]  = 64'h000000000000808B; RC[5]  = 64'h0000000080000001;
        RC[6]  = 64'h8000000080008081; RC[7]  = 64'h8000000000008009;
        RC[8]  = 64'h000000000000008A; RC[9]  = 64'h0000000000000088;
        RC[10] = 64'h0000000080008009; RC[11] = 64'h000000008000000A;
        RC[12] = 64'h000000008000808B; RC[13] = 64'h800000000000008B;
        RC[14] = 64'h8000000000008089; RC[15] = 64'h8000000000008003;
        RC[16] = 64'h8000000000008002; RC[17] = 64'h8000000000000080;
        RC[18] = 64'h000000000000800A; RC[19] = 64'h800000008000000A;
        RC[20] = 64'h8000000080008081; RC[21] = 64'h8000000000008080;
        RC[22] = 64'h0000000080000001; RC[23] = 64'h8000000080008008;
    end

    logic [63:0] tb_state [0:24];
    logic [63:0] tb_C [0:4];
    logic [63:0] tb_D [0:4];
    logic [63:0] tb_B [0:24];
    logic [1599:0] golden_out;

    task automatic calculate_keccak_golden();
        integer rnd, x, y;
        for (rnd = 0; rnd < 24; rnd = rnd + 1) begin
            // Theta
            for (x = 0; x < 5; x = x + 1) begin
                tb_C[x] = tb_state[x] ^ tb_state[x+5] ^ tb_state[x+10] ^ tb_state[x+15] ^ tb_state[x+20];
            end
            for (x = 0; x < 5; x = x + 1) begin
                tb_D[x] = tb_C[(x+4)%5] ^ {tb_C[(x+1)%5][62:0], tb_C[(x+1)%5][63]};
            end
            for (y = 0; y < 5; y = y + 1) begin
                for (x = 0; x < 5; x = x + 1) begin
                    tb_state[y*5 + x] = tb_state[y*5 + x] ^ tb_D[x];
                end
            end

            // Rho and Pi
            tb_B[0]  = tb_state[0];
            tb_B[10] = {tb_state[1][62:0], tb_state[1][63]};
            tb_B[7]  = {tb_state[10][60:0], tb_state[10][63:61]};
            tb_B[11] = {tb_state[7][57:0], tb_state[7][63:58]};
            tb_B[17] = {tb_state[11][53:0], tb_state[11][63:54]};
            tb_B[18] = {tb_state[17][48:0], tb_state[17][63:49]};
            tb_B[3]  = {tb_state[18][42:0], tb_state[18][63:43]};
            tb_B[5]  = {tb_state[3][35:0], tb_state[3][63:36]};
            tb_B[16] = {tb_state[5][27:0], tb_state[5][63:28]};
            tb_B[8]  = {tb_state[16][18:0], tb_state[16][63:19]};
            tb_B[21] = {tb_state[8][8:0], tb_state[8][63:9]};
            tb_B[24] = {tb_state[21][61:0], tb_state[21][63:62]};
            tb_B[4]  = {tb_state[24][49:0], tb_state[24][63:50]};
            tb_B[15] = {tb_state[4][36:0], tb_state[4][63:37]};
            tb_B[23] = {tb_state[15][22:0], tb_state[15][63:23]};
            tb_B[19] = {tb_state[23][7:0], tb_state[23][63:8]};
            tb_B[13] = {tb_state[19][55:0], tb_state[19][63:56]};
            tb_B[12] = {tb_state[13][38:0], tb_state[13][63:39]};
            tb_B[2]  = {tb_state[12][20:0], tb_state[12][63:21]};
            tb_B[20] = {tb_state[2][1:0], tb_state[2][63:2]};
            tb_B[14] = {tb_state[20][45:0], tb_state[20][63:46]};
            tb_B[22] = {tb_state[14][24:0], tb_state[14][63:25]};
            tb_B[9]  = {tb_state[22][2:0], tb_state[22][63:3]};
            tb_B[6]  = {tb_state[9][43:0], tb_state[9][63:44]};
            tb_B[1]  = {tb_state[6][19:0], tb_state[6][63:20]};

            // Chi
            for (y = 0; y < 5; y = y + 1) begin
                for (x = 0; x < 5; x = x + 1) begin
                    tb_state[y*5 + x] = tb_B[y*5 + x] ^ ((~tb_B[y*5 + ((x+1)%5)]) & tb_B[y*5 + ((x+2)%5)]);
                end
            end

            // Iota
            tb_state[0] = tb_state[0] ^ RC[rnd];
        end

        // Pack to 1600-bit output
        for (x = 0; x < 25; x = x + 1) begin
            golden_out[x*64 +: 64] = tb_state[x];
        end
    endtask

    // =========================================================
    // 5. TEST SEQUENCE
    // =========================================================
    integer tc, i;
    logic [63:0] random_word;

    initial begin
        // Reset
        clk   = 0;
        rst_n = 0;
        start = 0;
        state_in = 0;
        // Step 3.K1: legacy mode for direct state_in load on start
        load_on_start = 1'b1;
        init_pulse    = 1'b0;
        xor_we        = 1'b0;
        xor_byte_addr = 8'd0;
        xor_byte_data = 8'd0;

        $display("=================================================");
        $display("   STARTING BATCH TEST: KECCAK-F[1600] CORE      ");
        $display("=================================================");

        #20;
        rst_n = 1;
        #10;

        for (tc = 0; tc < 5; tc = tc + 1) begin
            $display("-------------------------------------------------");
            $display(">> RUNNING TESTCASE %0d / 5", tc + 1);

            // Generate 1600 random bits
            for (i = 0; i < 25; i = i + 1) begin
                random_word = {$urandom, $urandom};
                state_in[i*64 +: 64] = random_word;
                tb_state[i] = random_word;
            end

            // Calculate Golden Reference
            calculate_keccak_golden();

            // Kickoff Hardware
            @(negedge clk);
            start = 1;
            @(negedge clk);
            start = 0;

            wait(done);
            @(negedge clk);

            $display("   [PERFORMANCE] Keccak permutation took %0d clock cycles. (Theory: 1 load + 24 rounds = ~24)", cycle_count);

            // Verification
            if (state_out === golden_out) begin
                $display(">> [SUCCESS] Testcase %0d PASSED 100%%!", tc + 1);
            end else begin
                $display(">> [FAILED] Output mismatch in Testcase %0d.", tc + 1);
                // Print the first mismatching word for debugging
                for (i = 0; i < 25; i = i + 1) begin
                    if (state_out[i*64 +: 64] !== golden_out[i*64 +: 64]) begin
                        $display("   [DEBUG] Word %0d - Expected: %16h, Got: %16h", i, golden_out[i*64 +: 64], state_out[i*64 +: 64]);
                    end
                end
                $finish;
            end
        end

        $display("=================================================");
        $display("   ALL 5 TESTCASES PASSED FLAWLESSLY! CONGRATS!  ");
        $display("=================================================");
        
        #50;
        $finish;
    end

endmodule