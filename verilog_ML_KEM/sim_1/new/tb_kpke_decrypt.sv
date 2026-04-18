`timescale 1ns / 1ps

module tb_kpke_decrypt;
    localparam int DEFAULT_MAX_KATS = 100;
    localparam int TIMEOUT_CYCLES = 1000000;

    reg         clk;
    reg         rst_n;
    reg         start;
    wire        busy;
    reg         in_we;
    reg         in_sel;
    reg [10:0]  in_addr;
    reg [7:0]   in_wdata;
    reg         out_rd;
    reg [4:0]   out_addr;
    wire [7:0]  out_rdata;
    wire        out_valid;

    wire        done;
    wire        msg_we;
    wire [4:0]  msg_addr;
    wire [7:0]  msg_dout;
    wire [255:0] m_out;

    kpke_decrypt dut (
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
        .msg_we(msg_we),
        .msg_addr(msg_addr),
        .msg_dout(msg_dout),
        .m_out(m_out)
    );

    always #5 clk = ~clk;

    reg [7:0] dk_bytes [0:1151];
    reg [7:0] ct_bytes [0:1087];
    reg [7:0] exp_m    [0:31];
    reg [7:0] msg_mem  [0:31];

    integer i;

    always @(posedge clk) begin
        if (msg_we) begin
            if ((^msg_addr === 1'bx) || (msg_addr > 5'd31)) begin
                $display("ERROR: msg_addr out of range: %0d", msg_addr);
                $fatal(1);
            end
            msg_mem[msg_addr] <= msg_dout;
        end
    end

    function int hex_char_to_val(input byte c);
        if (c >= "0" && c <= "9") return c - "0";
        if (c >= "a" && c <= "f") return c - "a" + 10;
        if (c >= "A" && c <= "F") return c - "A" + 10;
        return 0;
    endfunction

    task automatic load_inputs;
        integer k;
        begin
            for (k = 0; k < 1152; k = k + 1) begin
                @(posedge clk);
                in_we    <= 1'b1;
                in_sel   <= 1'b0;
                in_addr  <= k[10:0];
                in_wdata <= dk_bytes[k];
            end
            for (k = 0; k < 1088; k = k + 1) begin
                @(posedge clk);
                in_we    <= 1'b1;
                in_sel   <= 1'b1;
                in_addr  <= k[10:0];
                in_wdata <= ct_bytes[k];
            end
            @(posedge clk);
            in_we <= 1'b0;
            for (k = 0; k < 32; k = k + 1) begin
                msg_mem[k] = 8'h00;
            end
        end
    endtask

    task automatic reset_dut;
        begin
            rst_n  = 1'b0;
            start  = 1'b0;
            in_we  = 1'b0;
            in_sel = 1'b0;
            in_addr = 11'd0;
            in_wdata = 8'd0;
            out_rd = 1'b0;
            out_addr = 5'd0;
            repeat (3) @(posedge clk);
            rst_n  = 1'b1;
            @(posedge clk);
        end
    endtask

    task automatic run_one_kat(input int kat_idx);
        integer watchdog;
        integer cycles;
        integer b;
        integer kat_errors;
        reg [7:0] got_stream;
        reg [7:0] got_packed;
        begin
            reset_dut();
            load_inputs();
            kat_errors = 0;

            @(posedge clk);
            start = 1'b1;
            @(posedge clk);
            start = 1'b0;

            watchdog = 0;
            cycles   = 0;
            while (!done && watchdog < TIMEOUT_CYCLES) begin
                @(posedge clk);
                watchdog = watchdog + 1;
                cycles   = cycles + 1;
            end

            if (!done) begin
                $display("ERROR: TIMEOUT at KAT #%0d after %0d cycles", kat_idx, watchdog);
                kat_errors = kat_errors + 1;
            end

            for (b = 0; b < 32; b = b + 1) begin
                got_packed = m_out[b*8 +: 8];
                if (got_packed !== exp_m[b]) begin
                    $display("ERROR: KAT #%0d packed mismatch at m[%0d]: exp=%02x got=%02x", kat_idx, b, exp_m[b], got_packed);
                    kat_errors = kat_errors + 1;
                end
            end

            for (b = 0; b < 32; b = b + 1) begin
                @(posedge clk);
                out_addr <= b[4:0];
                out_rd   <= 1'b1;
                @(posedge clk);
                out_rd   <= 1'b0;
                #1;
                if (!out_valid) begin
                    $display("ERROR: KAT #%0d out_valid low at m[%0d]", kat_idx, b);
                    kat_errors = kat_errors + 1;
                end
                got_stream = out_rdata;
                if (got_stream !== exp_m[b]) begin
                    $display("ERROR: KAT #%0d stream mismatch at m[%0d]: exp=%02x got=%02x", kat_idx, b, exp_m[b], got_stream);
                    kat_errors = kat_errors + 1;
                end
            end

            if (kat_errors == 0) begin
                $display("KAT #%0d PASSED in %0d cycles", kat_idx, cycles);
            end else begin
                error_count = error_count + kat_errors;
                $display("KAT #%0d FAILED with %0d mismatches/errors in %0d cycles", kat_idx, kat_errors, cycles);
            end
        end
    endtask

    integer fd;
    integer status;
    integer kat_count;
    integer error_count;
    integer max_kats;
    integer parsed_val;
    string line;
    bit have_sk;
    bit have_m;
    bit have_ct;

    initial begin
        clk      = 1'b0;
        rst_n    = 1'b0;
        start    = 1'b0;
        in_we     = 1'b0;
        in_sel    = 1'b0;
        in_addr   = 11'd0;
        in_wdata  = 8'd0;
        out_rd    = 1'b0;
        out_addr  = 5'd0;

        fd = $fopen("D:/HCMUT/Year_4/252/CA/Source/DACN/vitis_ML_KEM/src/KAT_768.txt", "r");
        if (fd == 0) begin
            $display("ERROR: Cannot open KAT_768.txt");
            $finish;
        end

        kat_count = 0;
        error_count = 0;
        have_sk   = 1'b0;
        have_m    = 1'b0;
        have_ct   = 1'b0;
        max_kats  = DEFAULT_MAX_KATS;
        if ($value$plusargs("MAX_KATS=%d", max_kats)) begin
            $display("INFO: Override MAX_KATS from plusarg = %0d", max_kats);
        end

        $display("===== K-PKE Decrypt KAT Testbench =====");
        $display("TB_REV: 2026-04-18 full-kat-default");

        while (!$feof(fd)) begin
            status = $fgets(line, fd);

            if (line.substr(0, 4) == "sk = ") begin
                for (i = 0; i < 1152; i = i + 1) begin
                    parsed_val = (hex_char_to_val(line[5 + i*2]) << 4) |
                                 hex_char_to_val(line[5 + i*2 + 1]);
                    dk_bytes[i] = parsed_val[7:0];
                end
                have_sk = 1'b1;
            end else if (line.substr(0, 3) == "m = ") begin
                for (i = 0; i < 32; i = i + 1) begin
                    parsed_val = (hex_char_to_val(line[4 + i*2]) << 4) |
                                 hex_char_to_val(line[4 + i*2 + 1]);
                    exp_m[i] = parsed_val[7:0];
                end
                have_m = 1'b1;
            end else if (line.substr(0, 4) == "ct = ") begin
                for (i = 0; i < 1088; i = i + 1) begin
                    parsed_val = (hex_char_to_val(line[5 + i*2]) << 4) |
                                 hex_char_to_val(line[5 + i*2 + 1]);
                    ct_bytes[i] = parsed_val[7:0];
                end
                have_ct = 1'b1;
            end

            if (have_sk && have_m && have_ct) begin
                kat_count = kat_count + 1;
                run_one_kat(kat_count);

                have_sk = 1'b0;
                have_m  = 1'b0;
                have_ct = 1'b0;

                if (kat_count >= max_kats) begin
                    $display("Reached MAX_KATS=%0d, stopping.", max_kats);
                    break;
                end
            end
        end

        $fclose(fd);
        if (error_count == 0) begin
            $display("ALL TESTS PASSED: %0d KAT vectors", kat_count);
        end else begin
            $display("TEST FAILED: %0d total mismatches/errors across %0d KAT vectors", error_count, kat_count);
            $fatal(1);
        end
        $finish;
    end

endmodule
