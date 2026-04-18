`timescale 1ns / 1ps

module tb_ml_kem_keygen();
    localparam bit DEBUG_VERBOSE = 1'b0;
    localparam bit ENABLE_HPK_STREAM_CHECK = 1'b0;
    localparam int KEYGEN_TIMEOUT_CYCLES = 500000;
    localparam int ST_HASH_H_PK_SEND = 41;

    // Clock and Reset
    reg clk;
    reg rst_n;
    
    // Inputs
    reg         start;
    reg [255:0] seed_d; // 32 bytes
    reg [255:0] seed_z; // 32 bytes
    
    // Outputs
    wire        done;
    wire        pk_we;
    wire [10:0] pk_addr;
    wire [7:0]  pk_dout;
    
    wire        sk_we;
    wire [11:0] sk_addr;
    wire [7:0]  sk_dout;
    
    // Instantiate DUT
    ml_kem_keygen dut (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .done(done),
        .seed_d_in(seed_d),
        .seed_z_in(seed_z),
        .pk_we(pk_we),
        .pk_addr(pk_addr),
        .pk_dout(pk_dout),
        .sk_we(sk_we),
        .sk_addr(sk_addr),
        .sk_dout(sk_dout)
    );
    
    // Clock generation
    always #5 clk = ~clk; // 100MHz
    
    // local memories for output capturing
    reg [7:0] pk_mem [0:1183];
    reg [7:0] sk_mem [0:2399];
    
    always @(posedge clk) begin
        if (pk_we) pk_mem[pk_addr] <= pk_dout;
        if (sk_we) sk_mem[sk_addr] <= sk_dout;
    end

    // Basic protocol/range guards: catch invalid write addressing early
    always @(posedge clk) begin
        if (pk_we && (pk_addr >= 11'd1184)) begin
            $display("ERROR: pk_addr out of range: %0d", pk_addr);
            $fatal(1);
        end
        if (sk_we && (sk_addr >= 12'd2400)) begin
            $display("ERROR: sk_addr out of range: %0d", sk_addr);
            $fatal(1);
        end
    end
    
    // Expected memories
    reg [7:0] expected_pk [0:1183];
    reg [7:0] expected_sk [0:2399];
    
    logic pk_fail;

    // -----------------------------------------------------------------
    // Deep debug: pump + parse + pw + add
    // -----------------------------------------------------------------
    // Ghi chú cơ chế hoạt động:
    // - pump: Cơ chế điều hướng dữ liệu (Routing/Memory Interface) trỏ giữa các S, E, RAM_A, B...
    // - parse: (Poly Parse Inline Top) Mạch tiêu thụ dòng byte ngẫu nhiên từ XOF (SHAKE128/256), loại bỏ các giá trị >= 3329 và gom thành các hệ số nguyên để tạo đa thức trong vành R_q.
    // - pw: Mạch nhân từng thành phần đa thức (Point-Wise Multiplication).
    // - add: Mạch cộng và tích lũy (Accumulation).
    always @(posedge clk) begin
        if (DEBUG_VERBOSE) begin
            if (pk_we && pk_addr < 4) begin
                $display("[PK_WR] addr=%0d data=%02h t=%0t", pk_addr, pk_dout, $time);
            end
            if (sk_we && sk_addr >= 12'd2336 && sk_addr < 12'd2344) begin
                $display("[SK_WR_HPK] addr=%0d data=%02h t=%0t", sk_addr, sk_dout, $time);
            end

            if (dut.state == 33 && dut.pump_cnt < 4) begin // S_PUMP = 33
                $display("[PUMP] src=%0d dst=%0d i=%0d j=%0d rd=%0d wr=%0d we=%0b data=%h t=%0t",
                    dut.pump_src_sel, dut.pump_dst_sel,
                    dut.i_idx, dut.j_idx,
                    dut.pump_rd_addr, dut.pump_wr_addr,
                    dut.pump_we, dut.pump_read_data, $time);
            end

            if (dut.init_keccak) begin
                $display("[KECCAK_INIT] hash_type=%0d i=%0d j=%0d state=%0d t=%0t",
                    dut.hash_type, dut.i_idx, dut.j_idx, dut.state, $time);
            end

            if (dut.finalize_keccak) begin
                $display("[KECCAK_FINAL] hash_type=%0d i=%0d j=%0d state=%0d t=%0t",
                    dut.hash_type, dut.i_idx, dut.j_idx, dut.state, $time);
            end

            if (dut.parse_start) begin
                $display("[PARSE_START] i=%0d j=%0d state=%0d t=%0t",
                    dut.i_idx, dut.j_idx, dut.state, $time);
            end

            if (dut.k_dout_valid && dut.parse_k_dout_ready) begin
                $display("[SHAKE_BYTE] i=%0d j=%0d byte=%02h t=%0t",
                    dut.i_idx, dut.j_idx, dut.k_dout, $time);
            end

            if (dut.parse_ram_we_a0 || dut.parse_ram_we_a1) begin
                $display("[PARSE_WR] i=%0d j=%0d addr=%0d we0=%0b d0=%h we1=%0b d1=%h t=%0t",
                    dut.i_idx, dut.j_idx,
                    dut.parse_ram_addr,
                    dut.parse_ram_we_a0, dut.parse_ram_a0_din,
                    dut.parse_ram_we_a1, dut.parse_ram_a1_din,
                    $time);
            end

            if (dut.parse_done) begin
                $display("[PARSE_DONE] i=%0d j=%0d t=%0t",
                    dut.i_idx, dut.j_idx, $time);
            end

            if (dut.pw_start) begin
                $display("[PW_START] i=%0d j=%0d t=%0t", dut.i_idx, dut.j_idx, $time);
                if (dut.i_idx == 0 && dut.j_idx == 0) begin
                    $display("[PW_IN_MEM] A0=%h A1=%h B0=%h B1=%h t=%0t",
                        dut.u_pw.u_ram_a0.mem[0], dut.u_pw.u_ram_a1.mem[0],
                        dut.u_pw.u_ram_b0.mem[0], dut.u_pw.u_ram_b1.mem[0], $time);
                end
            end

            if (dut.pw_done) begin
                $display("[PW_DONE] i=%0d j=%0d t=%0t", dut.i_idx, dut.j_idx, $time);
                if (dut.i_idx == 0 && dut.j_idx == 0) begin
                    $display("[PW_OUT_MEM] O0=%h O1=%h t=%0t",
                        dut.u_pw.u_ram_a0.mem[0], dut.u_pw.u_ram_a1.mem[0], $time);
                end
            end

            if (dut.add_start) begin
                $display("[ADD_START] i=%0d j=%0d t=%0t", dut.i_idx, dut.j_idx, $time);
            end

            if (dut.add_done) begin
                $display("[ADD_DONE] i=%0d j=%0d t=%0t", dut.i_idx, dut.j_idx, $time);
            end

            if (dut.state == 26 && dut.k_dout_valid) begin // S_HASH_H_WAIT
                $display("[HPK_CAP] idx=%0d data=%02h t=%0t", dut.var_k, dut.k_dout, $time);
            end

            if (dut.state == 33 && dut.pump_src_sel == 8 && dut.pump_cnt < 4) begin
                $display("[PW_OUT] i=%0d j=%0d rd=%0d data=%h t=%0t",
                    dut.i_idx, dut.j_idx, dut.pump_rd_addr, dut.pump_read_data, $time);
            end

            if (dut.state == 33 && dut.pump_src_sel == 9 && dut.pump_cnt < 4) begin
                $display("[ADD_OUT] i=%0d j=%0d rd=%0d data=%h t=%0t",
                    dut.i_idx, dut.j_idx, dut.pump_rd_addr, dut.pump_read_data, $time);
            end
        end
    end

    // Read hex parsing helper
    function int hex_char_to_val(input byte c);
        if (c >= "0" && c <= "9") return c - "0";
        if (c >= "a" && c <= "f") return c - "a" + 10;
        if (c >= "A" && c <= "F") return c - "A" + 10;
        return 0;
    endfunction

    // Test sequence
    integer fd, status, i;
    string line;
    byte hex_char1, hex_char2;
    int data_val;
    int cycle_count;
    int kat_count;
    bit have_d, have_z, have_pk, have_sk;

    // -------- Cycle statistics --------
    localparam int MAX_KAT_STATS = 200; // >= so KAT thuc te (100)

    int cycle_hist    [0:MAX_KAT_STATS-1];
    int sorted_cycles [0:MAX_KAT_STATS-1];

    longint unsigned cycle_sum;
    int cycle_min, cycle_max;
    real cycle_mean, cycle_median;
    int p95_cycles, p99_cycles;

    int n, j, tmp, idx95, idx99;

    // Phase 6.1 checker: verify H(pk) absorb byte-order in runtime.
    int hpk_stream_idx;
    bit hpk_stream_started;

    task automatic reset_and_clear_dut();
        int t;
        begin
            rst_n = 0;
            repeat (2) @(posedge clk);
            rst_n = 1;
            @(posedge clk);

            for (t = 0; t < 1184; t++) pk_mem[t] = 8'h00;
            for (t = 0; t < 2400; t++) sk_mem[t] = 8'h00;

            hpk_stream_idx = 0;
            hpk_stream_started = 0;
        end
    endtask

    task automatic run_keygen_with_timeout(input string tag, output int cycles_out);
        int watchdog;
        begin
            $display("Starting %s...", tag);

            @(posedge clk);
            start = 1;
            @(posedge clk);
            start = 0;

            cycles_out = 0;
            watchdog = 0;
            while (!done && watchdog < KEYGEN_TIMEOUT_CYCLES) begin
                @(posedge clk);
                cycles_out++;
                watchdog++;
            end

            if (!done) begin
                $display("ERROR: TIMEOUT in %s after %0d cycles", tag, watchdog);
                $fatal(1);
            end

            $display("%s Done in %0d cycles.", tag, cycles_out);
        end
    endtask

    // Runtime H(pk) stream order checker.
    // Check absorbed bytes at Keccak input handshake (k_din_valid && k_din_ready),
    // not raw BRAM dout timing, to avoid false mismatches at block boundaries.
    always @(posedge clk) begin
        if (!rst_n) begin
            hpk_stream_idx <= 0;
            hpk_stream_started <= 0;
        end else if (ENABLE_HPK_STREAM_CHECK) begin
            #1;
            if (dut.state == ST_HASH_H_PK_SEND && dut.k_din_valid && dut.k_din_ready) begin
                if (hpk_stream_idx >= 1184) begin
                    $display("HPK stream overflow: idx=%0d data=%02x", hpk_stream_idx, dut.k_din);
                    $stop;
                end
                if (dut.k_din !== pk_mem[hpk_stream_idx]) begin
                    $display("HPK stream mismatch at idx %0d: expected pk_mem=%02x got din=%02x",
                             hpk_stream_idx, pk_mem[hpk_stream_idx], dut.k_din);
                    $stop;
                end
                hpk_stream_idx <= hpk_stream_idx + 1;
                hpk_stream_started <= 1;
            end
        end
    end


    initial begin
        clk = 0;
        rst_n = 0;
        start = 0;
        
        #20 rst_n = 1;
        
        fd = $fopen("D:/HCMUT/Year_4/252/CA/Source/DACN/vitis_ML_KEM/src/KAT_768.txt", "r");
        if (fd == 0) begin
            $display("ERROR: Cannot open D:/HCMUT/Year_4/252/CA/Source/DACN/vitis_ML_KEM/src/KAT_768.txt");
            $finish;
        end
        
        $display("======= ML-KEM-768 RTL Verification ========");
        kat_count = 0;
        have_d  = 0;
        have_z  = 0;
        have_pk = 0;
        have_sk = 0;

        cycle_sum = 0;
        cycle_min = 32'h7fffffff;
        cycle_max = 0;

        
        // Read all KAT vectors
        while (!$feof(fd)) begin
            status = $fgets(line, fd);
            if (line.substr(0, 3) == "d = ") begin
                for (i = 0; i < 32; i++) begin
                    data_val = (hex_char_to_val(line[4 + i*2]) << 4) | hex_char_to_val(line[4 + i*2 + 1]);
                    // Pack into 256-bit array
                    seed_d[i*8 +: 8] = data_val;
                end
                have_d = 1;
            end
            else if (line.substr(0, 3) == "z = ") begin
                for (i = 0; i < 32; i++) begin
                    data_val = (hex_char_to_val(line[4 + i*2]) << 4) | hex_char_to_val(line[4 + i*2 + 1]);
                    seed_z[i*8 +: 8] = data_val;
                end
                have_z = 1;
            end
            else if (line.substr(0, 4) == "pk = ") begin
                for (i = 0; i < 1184; i++) begin
                    expected_pk[i] = (hex_char_to_val(line[5 + i*2]) << 4) | hex_char_to_val(line[5 + i*2 + 1]);
                end
                have_pk = 1;
            end
            else if (line.substr(0, 4) == "sk = ") begin
                for (i = 0; i < 2400; i++) begin
                    expected_sk[i] = (hex_char_to_val(line[5 + i*2]) << 4) | hex_char_to_val(line[5 + i*2 + 1]);
                end
                have_sk = 1;
                 
                // Finished parsing one vector, run test
                if (!(have_d && have_z && have_pk && have_sk)) begin
                    $display("ERROR: Incomplete KAT vector at index %0d", kat_count);
                    $finish;
                end
                kat_count = kat_count + 1;

                // Re-initialize DUT and clear captures before each KAT run
                reset_and_clear_dut();
                run_keygen_with_timeout($sformatf("KeyGen KAT #%0d", kat_count), cycle_count);

                if (ENABLE_HPK_STREAM_CHECK) begin
                    if (!hpk_stream_started) begin
                        $display("HPK stream checker: stream never started in KAT #%0d", kat_count);
                        $stop;
                    end
                    if (hpk_stream_idx != 1184) begin
                        $display("HPK stream checker: expected 1184 bytes, got %0d in KAT #%0d", hpk_stream_idx, kat_count);
                        $stop;
                    end
                end

                if (kat_count > MAX_KAT_STATS) begin
                    $display("ERROR: MAX_KAT_STATS=%0d is too small", MAX_KAT_STATS);
                    $finish;
                end

                cycle_hist[kat_count-1] = cycle_count;
                cycle_sum = cycle_sum + cycle_count;

                if (cycle_count < cycle_min) cycle_min = cycle_count;
                if (cycle_count > cycle_max) cycle_max = cycle_count;

                
                // Verify PK
                pk_fail = 0;
                for (i = 0; i < 1184; i = i + 1) begin
                    if (pk_mem[i] !== expected_pk[i]) begin
                        $display("PK Mismatch at byte %0d: Expected %02x, Got %02x", i, expected_pk[i], pk_mem[i]);
                        $stop;
                    end
                end
                $display("PK Match: PASSED");

                // Compare SK
                for (i = 0; i < 2400; i++) begin
                    if (sk_mem[i] !== expected_sk[i]) begin
                        $display("SK Mismatch at byte %0d: Expected %02x, Got %02x", i, expected_sk[i], sk_mem[i]);
                        $stop;
                    end
                end
                $display("SK Match: PASSED");
                $display("KAT #%0d PASSED", kat_count);

                // Prepare to parse next vector
                have_d  = 0;
                have_z  = 0;
                have_pk = 0;
                have_sk = 0;
            end
        end
        
        $fclose(fd);
        $display("ALL KAT PASSED: %0d vectors", kat_count);

        // -------- Final cycle report --------
        n = kat_count;

        // copy for sorting
        for (i = 0; i < n; i = i + 1) begin
            sorted_cycles[i] = cycle_hist[i];
        end

        // insertion sort (ascending)
        for (i = 1; i < n; i = i + 1) begin
            tmp = sorted_cycles[i];
            j = i - 1;
            while ((j >= 0) && (sorted_cycles[j] > tmp)) begin
                sorted_cycles[j+1] = sorted_cycles[j];
                j = j - 1;
            end
            sorted_cycles[j+1] = tmp;
        end

        cycle_mean = (n > 0) ? (1.0 * cycle_sum / n) : 0.0;

        // median
        if (n == 0) begin
            cycle_median = 0.0;
        end else if ((n % 2) == 1) begin
            cycle_median = sorted_cycles[n/2];
        end else begin
            cycle_median = 0.5 * (sorted_cycles[(n/2)-1] + sorted_cycles[n/2]);
        end

        // nearest-rank index for p95/p99
        idx95 = ((95*n + 99)/100) - 1;
        idx99 = ((99*n + 99)/100) - 1;
        if (idx95 < 0) idx95 = 0;
        if (idx99 < 0) idx99 = 0;
        if (idx95 >= n) idx95 = n-1;
        if (idx99 >= n) idx99 = n-1;

        p95_cycles = (n > 0) ? sorted_cycles[idx95] : 0;
        p99_cycles = (n > 0) ? sorted_cycles[idx99] : 0;

        $display("=== CYCLE STATS (%0d KAT) ===", n);
        $display("min    = %0d", cycle_min);
        $display("max    = %0d", cycle_max);
        $display("mean   = %0.2f", cycle_mean);
        $display("median = %0.2f", cycle_median);
        $display("p95    = %0d", p95_cycles);
        $display("p99    = %0d", p99_cycles);

        // -------- Directed boundary tests (integration-level) --------
        $display("=== DIRECTED BOUNDARY TESTS ===");

        // Boundary 1: all-zero seeds
        seed_d = 256'h0;
        seed_z = 256'h0;
        reset_and_clear_dut();
        run_keygen_with_timeout("Boundary all-zero seeds", cycle_count);
        if (ENABLE_HPK_STREAM_CHECK && hpk_stream_idx != 1184) begin
            $display("HPK stream checker (boundary zero): expected 1184 bytes, got %0d", hpk_stream_idx);
            $stop;
        end
        $display("Boundary all-zero seeds: PASSED");

        // Boundary 2: all-0xFF seeds
        seed_d = {256{1'b1}};
        seed_z = {256{1'b1}};
        reset_and_clear_dut();
        run_keygen_with_timeout("Boundary all-FF seeds", cycle_count);
        if (ENABLE_HPK_STREAM_CHECK && hpk_stream_idx != 1184) begin
            $display("HPK stream checker (boundary all-FF): expected 1184 bytes, got %0d", hpk_stream_idx);
            $stop;
        end
        $display("Boundary all-FF seeds: PASSED");

        $finish;
    end
endmodule
