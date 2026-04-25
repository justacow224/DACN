`timescale 1ns / 1ps

module tb_ml_kem_decaps;
    localparam int DEFAULT_MAX_KATS = 10;
    localparam int TIMEOUT_CYCLES   = 4000000;
    localparam int TIMING_DELTA_MAX = 10;

    reg         clk;
    reg         rst_n;
    reg         start;
    wire        busy;
    wire        done;

    reg         in_we;
    reg         in_sel;
    reg [11:0]  in_addr;
    reg [7:0]   in_wdata;

    reg         out_rd;
    reg [10:0]  out_addr;
    wire [7:0]  out_rdata;
    wire        out_valid;

    wire [255:0] ss_out;

    ml_kem_decaps dut (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .busy(busy),
        .done(done),
        .in_we(in_we),
        .in_sel(in_sel),
        .in_addr(in_addr),
        .in_wdata(in_wdata),
        .out_rd(out_rd),
        .out_addr(out_addr),
        .out_rdata(out_rdata),
        .out_valid(out_valid),
        .ss_out(ss_out)
    );

    always #5 clk = ~clk;

    reg [7:0] sk_bytes      [0:2399];
    reg [7:0] ct_bytes      [0:1087];
    reg [7:0] ct_tampered   [0:1087];
    reg [7:0] exp_ss        [0:31];
    reg [7:0] got_ss_match  [0:31];
    reg [7:0] got_ss_fail   [0:31];

    integer i;

    function int hex_char_to_val(input byte c);
        if (c >= "0" && c <= "9") return c - "0";
        if (c >= "a" && c <= "f") return c - "a" + 10;
        if (c >= "A" && c <= "F") return c - "A" + 10;
        return 0;
    endfunction

    task automatic reset_dut;
        begin
            rst_n    = 1'b0;
            start    = 1'b0;
            in_we    = 1'b0;
            in_sel   = 1'b0;
            in_addr  = 12'd0;
            in_wdata = 8'd0;
            out_rd   = 1'b0;
            out_addr = 11'd0;
            repeat (4) @(posedge clk);
            rst_n = 1'b1;
            @(posedge clk);
        end
    endtask

    task automatic preload_inputs(input bit use_tampered_ct);
        begin
            for (i = 0; i < 2400; i = i + 1) begin
                in_we    = 1'b1;
                in_sel   = 1'b0;
                in_addr  = i[11:0];
                in_wdata = sk_bytes[i];
                @(posedge clk);
            end
            for (i = 0; i < 1088; i = i + 1) begin
                in_we    = 1'b1;
                in_sel   = 1'b1;
                in_addr  = i[11:0];
                if (use_tampered_ct) in_wdata = ct_tampered[i];
                else                 in_wdata = ct_bytes[i];
                @(posedge clk);
            end
            in_we = 1'b0;
            @(posedge clk);
        end
    endtask

    task automatic run_decaps_once(
        input bit use_tampered_ct,
        output integer cycles
    );
        integer wd;
        integer b;
        begin
            reset_dut();
            preload_inputs(use_tampered_ct);

            start = 1'b1;
            @(posedge clk);
            start = 1'b0;

            wd = 0;
            while (!done && wd < TIMEOUT_CYCLES) begin
                @(posedge clk);
                wd = wd + 1;
            end
            cycles = wd;

            if (!done) begin
                $display("ERROR: TIMEOUT while waiting decaps done");
                $fatal(1);
            end

            for (b = 0; b < 32; b = b + 1) begin
                if (use_tampered_ct) begin
                    got_ss_fail[b] = ss_out[b*8 +: 8];
                end else begin
                    got_ss_match[b] = ss_out[b*8 +: 8];
                end
            end
        end
    endtask

    function automatic int abs_int(input int v);
        if (v < 0) abs_int = -v;
        else       abs_int = v;
    endfunction

    integer fd;
    integer status;
    integer kat_count;
    integer err_count;
    integer max_kats;
    integer parsed_val;
    integer cycles_match;
    integer cycles_fail;
    integer timing_diff;
    string line;
    string kat_file;
    bit have_sk;
    bit have_ct;
    bit have_ss;
    bit fail_diff_seen;

    initial begin
        clk      = 1'b0;
        rst_n    = 1'b0;
        start    = 1'b0;
        in_we    = 1'b0;
        in_sel   = 1'b0;
        in_addr  = 12'd0;
        in_wdata = 8'd0;
        out_rd   = 1'b0;
        out_addr = 11'd0;

        kat_file = "./KAT_768.txt";
        if ($value$plusargs("KAT_FILE=%s", kat_file)) begin
            $display("INFO: Override KAT_FILE=%s", kat_file);
        end

        fd = $fopen(kat_file, "r");
        if (fd == 0) begin
            $display("ERROR: Cannot open KAT_768.txt at %s", kat_file);
            $finish;
        end

        max_kats = DEFAULT_MAX_KATS;
        if ($value$plusargs("MAX_KATS=%d", max_kats)) begin
            $display("INFO: Override MAX_KATS=%0d", max_kats);
        end

        kat_count = 0;
        err_count = 0;
        have_sk = 1'b0;
        have_ct = 1'b0;
        have_ss = 1'b0;

        $display("===== ML-KEM Decaps KAT Testbench =====");

        while (!$feof(fd)) begin
            status = $fgets(line, fd);

            if (line.substr(0, 4) == "sk = ") begin
                for (i = 0; i < 2400; i = i + 1) begin
                    parsed_val = (hex_char_to_val(line[5 + i*2]) << 4) |
                                 hex_char_to_val(line[5 + i*2 + 1]);
                    sk_bytes[i] = parsed_val[7:0];
                end
                have_sk = 1'b1;
            end else if (line.substr(0, 4) == "ct = ") begin
                for (i = 0; i < 1088; i = i + 1) begin
                    parsed_val = (hex_char_to_val(line[5 + i*2]) << 4) |
                                 hex_char_to_val(line[5 + i*2 + 1]);
                    ct_bytes[i] = parsed_val[7:0];
                end
                have_ct = 1'b1;
            end else if (line.substr(0, 4) == "ss = ") begin
                for (i = 0; i < 32; i = i + 1) begin
                    parsed_val = (hex_char_to_val(line[5 + i*2]) << 4) |
                                 hex_char_to_val(line[5 + i*2 + 1]);
                    exp_ss[i] = parsed_val[7:0];
                end
                have_ss = 1'b1;
            end

            if (have_sk && have_ct && have_ss) begin
                kat_count = kat_count + 1;

                run_decaps_once(1'b0, cycles_match);

                for (i = 0; i < 32; i = i + 1) begin
                    if (got_ss_match[i] !== exp_ss[i]) begin
                        if (i == 0) begin
                            $display("DBG match_reg=%0d xor_acc=%02x k_prime[0]=%02x k_reject[0]=%02x",
                                     dut.match_reg, dut.xor_acc, dut.k_prime[0], dut.k_reject[0]);
                            $display("DBG cmp_seen=%0d idx=%0d ct=%02x ct_prime=%02x enc_ct_count=%0d dec_m0=%02x",
                                     dut.dbg_cmp_seen, dut.dbg_cmp_idx, dut.dbg_ct_byte, dut.dbg_ct_prime_byte,
                                     dut.dbg_enc_ct_count, dut.core_m_out[7:0]);
                        end
                        $display("ERROR: KAT #%0d match ss mismatch at [%0d]: exp=%02x got=%02x",
                                 kat_count, i, exp_ss[i], got_ss_match[i]);
                        err_count = err_count + 1;
                    end
                end

                for (i = 0; i < 1088; i = i + 1) begin
                    ct_tampered[i] = ct_bytes[i];
                end
                ct_tampered[0] = ct_tampered[0] ^ 8'hFF;

                run_decaps_once(1'b1, cycles_fail);

                fail_diff_seen = 1'b0;
                for (i = 0; i < 32; i = i + 1) begin
                    if (got_ss_fail[i] !== exp_ss[i]) begin
                        fail_diff_seen = 1'b1;
                    end
                end
                if (!fail_diff_seen) begin
                    $display("ERROR: KAT #%0d tamper did not change ss", kat_count);
                    err_count = err_count + 1;
                end

                for (i = 0; i < 32; i = i + 1) begin
                    if (got_ss_fail[i] !== dut.k_reject[i]) begin
                        $display("ERROR: KAT #%0d reject mismatch at [%0d]: got=%02x reject=%02x",
                                 kat_count, i, got_ss_fail[i], dut.k_reject[i]);
                        err_count = err_count + 1;
                    end
                end

                timing_diff = abs_int(cycles_match - cycles_fail);
                if (timing_diff > TIMING_DELTA_MAX) begin
                    $display("ERROR: KAT #%0d timing delta too large: match=%0d fail=%0d diff=%0d",
                             kat_count, cycles_match, cycles_fail, timing_diff);
                    err_count = err_count + 1;
                end

                if (err_count == 0) begin
                    $display("KAT #%0d PASSED (match=%0d cycles, fail=%0d cycles)",
                             kat_count, cycles_match, cycles_fail);
                end else begin
                    $display("KAT #%0d cumulative errors=%0d", kat_count, err_count);
                end

                have_sk = 1'b0;
                have_ct = 1'b0;
                have_ss = 1'b0;

                if (kat_count >= max_kats) begin
                    $display("Reached MAX_KATS=%0d, stopping.", max_kats);
                    break;
                end
            end
        end

        $fclose(fd);
        if (err_count == 0) begin
            $display("ALL TESTS PASSED: %0d decaps KAT vectors", kat_count);
        end else begin
            $display("TEST FAILED: %0d mismatches/errors across %0d vectors", err_count, kat_count);
            $fatal(1);
        end
        $finish;
    end

endmodule
