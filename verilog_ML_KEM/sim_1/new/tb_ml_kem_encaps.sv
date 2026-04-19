`timescale 1ns / 1ps

module tb_ml_kem_encaps;
    localparam int DEFAULT_MAX_KATS = 10;
    localparam int TIMEOUT_CYCLES   = 3000000;

    reg         clk;
    reg         rst_n;
    reg         start;
    wire        busy;
    wire        done;

    reg         in_we;
    reg         in_sel;
    reg [10:0]  in_addr;
    reg [7:0]   in_wdata;

    reg         out_rd;
    reg         out_sel;
    reg [10:0]  out_addr;
    wire [7:0]  out_rdata;
    wire        out_valid;

    wire        ct_we;
    wire [10:0] ct_addr;
    wire [7:0]  ct_dout;
    wire [255:0] ss_out;

    ml_kem_encaps dut (
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
        .out_sel(out_sel),
        .out_addr(out_addr),
        .out_rdata(out_rdata),
        .out_valid(out_valid),
        .ct_we(ct_we),
        .ct_addr(ct_addr),
        .ct_dout(ct_dout),
        .ss_out(ss_out)
    );

    always #5 clk = ~clk;

    reg [7:0] pk_bytes [0:1183];
    reg [7:0] m_bytes  [0:31];
    reg [7:0] exp_ct   [0:1087];
    reg [7:0] exp_ss   [0:31];
    reg [7:0] ct_mem   [0:1087];

    integer i;

    always @(posedge clk) begin
        if (ct_we && ct_addr < 11'd1088) begin
            ct_mem[ct_addr] <= ct_dout;
        end
    end

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
            in_addr  = 11'd0;
            in_wdata = 8'd0;
            out_rd   = 1'b0;
            out_sel  = 1'b0;
            out_addr = 11'd0;
            repeat (4) @(posedge clk);
            rst_n = 1'b1;
            @(posedge clk);
        end
    endtask

    task automatic preload_inputs;
        begin
            for (i = 0; i < 1184; i = i + 1) begin
                in_we    = 1'b1;
                in_sel   = 1'b0;
                in_addr  = i[10:0];
                in_wdata = pk_bytes[i];
                @(posedge clk);
            end
            for (i = 0; i < 32; i = i + 1) begin
                in_we    = 1'b1;
                in_sel   = 1'b1;
                in_addr  = i[10:0];
                in_wdata = m_bytes[i];
                @(posedge clk);
            end
            in_we = 1'b0;
            @(posedge clk);

            for (i = 0; i < 1088; i = i + 1) begin
                ct_mem[i] = 8'h00;
            end
        end
    endtask

    task automatic run_one_kat(input int kat_idx, inout integer err_count);
        integer wd;
        integer b;
        integer cycles;
        reg [7:0] got_ss;
        begin
            reset_dut();
            preload_inputs();
            if (kat_idx == 1) begin
                $display("DBG KAT1 preload pk[0..3]=%02x %02x %02x %02x m[0..3]=%02x %02x %02x %02x",
                         pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3],
                         m_bytes[0],  m_bytes[1],  m_bytes[2],  m_bytes[3]);
                $display("DBG KAT1 dutbuf  ek[0..3]=%02x %02x %02x %02x m[0..3]=%02x %02x %02x %02x",
                         dut.ek_buf[0], dut.ek_buf[1], dut.ek_buf[2], dut.ek_buf[3],
                         dut.m_buf[0],  dut.m_buf[1],  dut.m_buf[2],  dut.m_buf[3]);
            end

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
                $display("ERROR: TIMEOUT at KAT #%0d", kat_idx);
                err_count = err_count + 1;
            end

            // Allow final stream writes to settle before compare.
            repeat (2) @(posedge clk);
            if (kat_idx == 1) begin
                $display("DBG KAT1 hash    h[0..3]=%02x %02x %02x %02x ss[0..3]=%02x %02x %02x %02x",
                         dut.h_buf[0], dut.h_buf[1], dut.h_buf[2], dut.h_buf[3],
                         dut.ss_buf[0], dut.ss_buf[1], dut.ss_buf[2], dut.ss_buf[3]);
            end

            // Compare ss from packed output.
            for (b = 0; b < 32; b = b + 1) begin
                got_ss = ss_out[b*8 +: 8];
                if (got_ss !== exp_ss[b]) begin
                    $display("ERROR: KAT #%0d ss mismatch at [%0d]: exp=%02x got=%02x",
                             kat_idx, b, exp_ss[b], got_ss);
                    err_count = err_count + 1;
                end
            end

            // Compare ct captured from streaming interface.
            for (b = 0; b < 1088; b = b + 1) begin
                if (ct_mem[b] !== exp_ct[b]) begin
                    $display("ERROR: KAT #%0d ct mismatch at [%0d]: exp=%02x got=%02x",
                             kat_idx, b, exp_ct[b], ct_mem[b]);
                    err_count = err_count + 1;
                end
            end

            if (err_count == 0) begin
                $display("KAT #%0d PASSED (cycles=%0d)", kat_idx, cycles);
            end else begin
                $display("KAT #%0d cumulative errors=%0d", kat_idx, err_count);
            end
        end
    endtask

    integer fd;
    integer status;
    integer scan_status;
    integer kat_count;
    integer err_count;
    integer max_kats;
    integer parsed_val;
    string token;
    string eq;
    string hex_str;
    bit have_pk;
    bit have_m;
    bit have_ct;
    bit have_ss;

    initial begin
        clk      = 1'b0;
        rst_n    = 1'b0;
        start    = 1'b0;
        in_we    = 1'b0;
        in_sel   = 1'b0;
        in_addr  = 11'd0;
        in_wdata = 8'd0;
        out_rd   = 1'b0;
        out_sel  = 1'b0;
        out_addr = 11'd0;

        fd = $fopen("D:/HCMUT/Year_4/252/CA/Source/DACN/vitis_ML_KEM/src/KAT_768.txt", "r");
        if (fd == 0) begin
            $display("ERROR: Cannot open KAT_768.txt");
            $finish;
        end

        max_kats = DEFAULT_MAX_KATS;
        if ($value$plusargs("MAX_KATS=%d", max_kats)) begin
            $display("INFO: Override MAX_KATS=%0d", max_kats);
        end

        kat_count = 0;
        err_count = 0;
        have_pk = 1'b0;
        have_m  = 1'b0;
        have_ct = 1'b0;
        have_ss = 1'b0;

        $display("===== ML-KEM Encaps KAT Testbench =====");

        while (!$feof(fd)) begin
            scan_status = $fscanf(fd, "%s", token);
            if (scan_status != 1) begin
                status = $fgetc(fd);
                continue;
            end

            if (token == "count") begin
                status = $fscanf(fd, "%s %d", eq, parsed_val);
                have_pk = 1'b0;
                have_m  = 1'b0;
                have_ct = 1'b0;
                have_ss = 1'b0;
            end else if (token == "pk") begin
                status = $fscanf(fd, "%s %s", eq, hex_str);
                if (status == 2 && hex_str.len() >= 1184*2) begin
                    for (i = 0; i < 1184; i = i + 1) begin
                        parsed_val = (hex_char_to_val(hex_str[i*2]) << 4) |
                                     hex_char_to_val(hex_str[i*2 + 1]);
                        pk_bytes[i] = parsed_val[7:0];
                    end
                    have_pk = 1'b1;
                end else begin
                    $display("ERROR: malformed pk token (len=%0d)", hex_str.len());
                end
            end else if (token == "m" || token == "msg") begin
                status = $fscanf(fd, "%s %s", eq, hex_str);
                if (status == 2 && hex_str.len() >= 32*2) begin
                    for (i = 0; i < 32; i = i + 1) begin
                        parsed_val = (hex_char_to_val(hex_str[i*2]) << 4) |
                                     hex_char_to_val(hex_str[i*2 + 1]);
                        m_bytes[i] = parsed_val[7:0];
                    end
                    have_m = 1'b1;
                end else begin
                    $display("ERROR: malformed m/msg token (len=%0d)", hex_str.len());
                end
            end else if (token == "ct") begin
                status = $fscanf(fd, "%s %s", eq, hex_str);
                if (status == 2 && hex_str.len() >= 1088*2) begin
                    for (i = 0; i < 1088; i = i + 1) begin
                        parsed_val = (hex_char_to_val(hex_str[i*2]) << 4) |
                                     hex_char_to_val(hex_str[i*2 + 1]);
                        exp_ct[i] = parsed_val[7:0];
                    end
                    have_ct = 1'b1;
                end else begin
                    $display("ERROR: malformed ct token (len=%0d)", hex_str.len());
                end
            end else if (token == "ss") begin
                status = $fscanf(fd, "%s %s", eq, hex_str);
                if (status == 2 && hex_str.len() >= 32*2) begin
                    for (i = 0; i < 32; i = i + 1) begin
                        parsed_val = (hex_char_to_val(hex_str[i*2]) << 4) |
                                     hex_char_to_val(hex_str[i*2 + 1]);
                        exp_ss[i] = parsed_val[7:0];
                    end
                    have_ss = 1'b1;
                end else begin
                    $display("ERROR: malformed ss token (len=%0d)", hex_str.len());
                end
            end

            if (have_pk && have_m && have_ct && have_ss) begin
                kat_count = kat_count + 1;
                run_one_kat(kat_count, err_count);

                have_pk = 1'b0;
                have_m  = 1'b0;
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
            $display("ALL TESTS PASSED: %0d encaps KAT vectors", kat_count);
        end else begin
            $display("TEST FAILED: %0d mismatches/errors across %0d vectors", err_count, kat_count);
            $fatal(1);
        end
        $finish;
    end

endmodule
