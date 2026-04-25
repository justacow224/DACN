`timescale 1ns / 1ps

module tb_kpke_encrypt;
    localparam int DEFAULT_MAX_KATS      = 10;
    localparam int KEYGEN_TIMEOUT_CYCLES = 1000000;
    localparam int ENC_TIMEOUT_CYCLES    = 2000000;
    localparam int DEC_TIMEOUT_CYCLES    = 1000000;

    reg clk;
    reg rst_n;

    // -------------------------------------------------------------
    // KeyGen
    // -------------------------------------------------------------
    reg         kg_start;
    reg [255:0] seed_d;
    reg [255:0] seed_z;
    wire        kg_done;
    wire        pk_we;
    wire [10:0] pk_addr;
    wire [7:0]  pk_dout;
    wire        sk_we;
    wire [11:0] sk_addr;
    wire [7:0]  sk_dout;

    ml_kem_keygen u_keygen (
        .clk(clk),
        .rst_n(rst_n),
        .start(kg_start),
        .done(kg_done),
        .seed_d_in(seed_d),
        .seed_z_in(seed_z),
        .pk_we(pk_we),
        .pk_addr(pk_addr),
        .pk_dout(pk_dout),
        .sk_we(sk_we),
        .sk_addr(sk_addr),
        .sk_dout(sk_dout)
    );

    // -------------------------------------------------------------
    // Encrypt
    // -------------------------------------------------------------
    reg         enc_start;
    wire        enc_busy;
    wire        enc_done;
    reg         enc_in_we;
    reg [1:0]   enc_in_sel;
    reg [10:0]  enc_in_addr;
    reg [7:0]   enc_in_wdata;
    reg         enc_out_rd;
    reg [10:0]  enc_out_addr;
    wire [7:0]  enc_out_rdata;
    wire        enc_out_valid;
    wire        enc_ct_we;
    wire [10:0] enc_ct_addr;
    wire [7:0]  enc_ct_dout;

    kpke_encrypt u_encrypt (
        .clk(clk),
        .rst_n(rst_n),
        .start(enc_start),
        .busy(enc_busy),
        .done(enc_done),
        .in_we(enc_in_we),
        .in_sel(enc_in_sel),
        .in_addr(enc_in_addr),
        .in_wdata(enc_in_wdata),
        .out_rd(enc_out_rd),
        .out_addr(enc_out_addr),
        .out_rdata(enc_out_rdata),
        .out_valid(enc_out_valid),
        .ct_we(enc_ct_we),
        .ct_addr(enc_ct_addr),
        .ct_dout(enc_ct_dout)
    );

    // -------------------------------------------------------------
    // Decrypt
    // -------------------------------------------------------------
    reg         dec_start;
    wire        dec_busy;
    wire        dec_done;
    reg         dec_in_we;
    reg         dec_in_sel;
    reg [10:0]  dec_in_addr;
    reg [7:0]   dec_in_wdata;
    reg         dec_out_rd;
    reg [4:0]   dec_out_addr;
    wire [7:0]  dec_out_rdata;
    wire        dec_out_valid;
    wire        dec_msg_we;
    wire [4:0]  dec_msg_addr;
    wire [7:0]  dec_msg_dout;
    wire [255:0] dec_m_out;

    kpke_decrypt u_decrypt (
        .clk(clk),
        .rst_n(rst_n),
        .start(dec_start),
        .busy(dec_busy),
        .done(dec_done),
        .in_we(dec_in_we),
        .in_sel(dec_in_sel),
        .in_addr(dec_in_addr),
        .in_wdata(dec_in_wdata),
        .out_rd(dec_out_rd),
        .out_addr(dec_out_addr),
        .out_rdata(dec_out_rdata),
        .out_valid(dec_out_valid),
        .msg_we(dec_msg_we),
        .msg_addr(dec_msg_addr),
        .msg_dout(dec_msg_dout),
        .m_out(dec_m_out)
    );

    always #5 clk = ~clk;

    reg [7:0] pk_mem  [0:1183];
    reg [7:0] sk_mem  [0:2399];
    reg [7:0] ct_mem  [0:1087];
    reg [7:0] m_in    [0:31];
    reg [7:0] r_in    [0:31];
    reg [7:0] dec_mem [0:31];

    integer i;
    integer b;

    always @(posedge clk) begin
        if (pk_we) pk_mem[pk_addr] <= pk_dout;
        if (sk_we) sk_mem[sk_addr] <= sk_dout;
        if (enc_ct_we && enc_ct_addr < 11'd1088) ct_mem[enc_ct_addr] <= enc_ct_dout;
        if (dec_msg_we) dec_mem[dec_msg_addr] <= dec_msg_dout;
    end

    function int hex_char_to_val(input byte c);
        if (c >= "0" && c <= "9") return c - "0";
        if (c >= "a" && c <= "f") return c - "a" + 10;
        if (c >= "A" && c <= "F") return c - "A" + 10;
        return 0;
    endfunction

    task automatic reset_dut;
        begin
            rst_n       = 1'b0;
            kg_start    = 1'b0;
            enc_start   = 1'b0;
            enc_in_we   = 1'b0;
            enc_in_sel  = 2'd0;
            enc_in_addr = 11'd0;
            enc_in_wdata= 8'd0;
            enc_out_rd  = 1'b0;
            enc_out_addr= 11'd0;

            dec_start   = 1'b0;
            dec_in_we   = 1'b0;
            dec_in_sel  = 1'b0;
            dec_in_addr = 11'd0;
            dec_in_wdata= 8'd0;
            dec_out_rd  = 1'b0;
            dec_out_addr= 5'd0;

            repeat (4) @(posedge clk);
            rst_n = 1'b1;
            @(posedge clk);
        end
    endtask

    task automatic run_keygen_once(output integer cycles);
        integer wd;
        begin
            @(posedge clk);
            kg_start <= 1'b1;
            @(posedge clk);
            kg_start <= 1'b0;
            wd = 0;
            while (!kg_done && wd < KEYGEN_TIMEOUT_CYCLES) begin
                @(posedge clk);
                wd = wd + 1;
            end
            cycles = wd;
            if (!kg_done) begin
                $display("ERROR: TIMEOUT in KeyGen after %0d cycles", wd);
                $fatal(1);
            end
        end
    endtask

    task automatic preload_encrypt_inputs;
        begin
            for (i = 0; i < 1184; i = i + 1) begin
                @(posedge clk);
                enc_in_we    <= 1'b1;
                enc_in_sel   <= 2'd0;
                enc_in_addr  <= i[10:0];
                enc_in_wdata <= pk_mem[i];
            end
            for (i = 0; i < 32; i = i + 1) begin
                @(posedge clk);
                enc_in_we    <= 1'b1;
                enc_in_sel   <= 2'd1;
                enc_in_addr  <= i[10:0];
                enc_in_wdata <= m_in[i];
            end
            for (i = 0; i < 32; i = i + 1) begin
                @(posedge clk);
                enc_in_we    <= 1'b1;
                enc_in_sel   <= 2'd2;
                enc_in_addr  <= i[10:0];
                enc_in_wdata <= r_in[i];
            end
            @(posedge clk);
            enc_in_we <= 1'b0;
        end
    endtask

    task automatic run_encrypt_once(output integer cycles);
        integer wd;
        begin
            @(posedge clk);
            enc_start <= 1'b1;
            @(posedge clk);
            enc_start <= 1'b0;
            wd = 0;
            while (!enc_done && wd < ENC_TIMEOUT_CYCLES) begin
                @(posedge clk);
                wd = wd + 1;
            end
            cycles = wd;
            if (!enc_done) begin
                $display("ERROR: TIMEOUT in K-PKE Encrypt after %0d cycles", wd);
                $fatal(1);
            end
        end
    endtask

    task automatic preload_decrypt_inputs;
        begin
            for (i = 0; i < 1152; i = i + 1) begin
                @(posedge clk);
                dec_in_we    <= 1'b1;
                dec_in_sel   <= 1'b0;
                dec_in_addr  <= i[10:0];
                dec_in_wdata <= sk_mem[i];
            end
            for (i = 0; i < 1088; i = i + 1) begin
                @(posedge clk);
                dec_in_we    <= 1'b1;
                dec_in_sel   <= 1'b1;
                dec_in_addr  <= i[10:0];
                dec_in_wdata <= ct_mem[i];
            end
            @(posedge clk);
            dec_in_we <= 1'b0;
        end
    endtask

    task automatic run_decrypt_once(output integer cycles);
        integer wd;
        begin
            @(posedge clk);
            dec_start <= 1'b1;
            @(posedge clk);
            dec_start <= 1'b0;
            wd = 0;
            while (!dec_done && wd < DEC_TIMEOUT_CYCLES) begin
                @(posedge clk);
                wd = wd + 1;
            end
            cycles = wd;
            if (!dec_done) begin
                $display("ERROR: TIMEOUT in K-PKE Decrypt after %0d cycles", wd);
                $fatal(1);
            end
        end
    endtask

    task automatic build_test_message(input int kat_idx);
        begin
            for (i = 0; i < 32; i = i + 1) begin
                m_in[i] = (kat_idx * 8'h11) ^ (i * 8'h03) ^ 8'h5A;
                r_in[i] = (kat_idx * 8'h07) ^ (i * 8'h29) ^ 8'hA5;
                dec_mem[i] = 8'h00;
            end
            for (i = 0; i < 1088; i = i + 1) begin
                ct_mem[i] = 8'h00;
            end
        end
    endtask

    task automatic check_roundtrip(input int kat_idx, inout integer err_count);
        reg [7:0] got_byte;
        begin
            for (b = 0; b < 32; b = b + 1) begin
                got_byte = dec_m_out[b*8 +: 8];
                if (got_byte !== m_in[b]) begin
                    $display("ERROR: KAT #%0d mismatch at m[%0d] exp=%02x got=%02x",
                             kat_idx, b, m_in[b], got_byte);
                    err_count = err_count + 1;
                end
            end
        end
    endtask

    integer fd;
    integer status;
    integer kat_count;
    integer err_count;
    integer max_kats;
    integer parsed_val;
    integer cyc_kg;
    integer cyc_enc;
    integer cyc_dec;
    string  line;
    string  kat_file;
    bit have_d;
    bit have_z;

    initial begin
        clk = 1'b0;
        rst_n = 1'b0;
        kg_start = 1'b0;
        enc_start = 1'b0;
        enc_in_we = 1'b0;
        enc_in_sel = 2'd0;
        enc_in_addr = 11'd0;
        enc_in_wdata = 8'd0;
        enc_out_rd = 1'b0;
        enc_out_addr = 11'd0;
        dec_start = 1'b0;
        dec_in_we = 1'b0;
        dec_in_sel = 1'b0;
        dec_in_addr = 11'd0;
        dec_in_wdata = 8'd0;
        dec_out_rd = 1'b0;
        dec_out_addr = 5'd0;

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
        have_d = 1'b0;
        have_z = 1'b0;

        $display("===== K-PKE Encrypt Roundtrip Testbench =====");

        while (!$feof(fd)) begin
            status = $fgets(line, fd);

            if (line.substr(0, 3) == "d = ") begin
                for (i = 0; i < 32; i = i + 1) begin
                    parsed_val = (hex_char_to_val(line[4 + i*2]) << 4) |
                                 hex_char_to_val(line[4 + i*2 + 1]);
                    seed_d[i*8 +: 8] = parsed_val[7:0];
                end
                have_d = 1'b1;
            end else if (line.substr(0, 3) == "z = ") begin
                for (i = 0; i < 32; i = i + 1) begin
                    parsed_val = (hex_char_to_val(line[4 + i*2]) << 4) |
                                 hex_char_to_val(line[4 + i*2 + 1]);
                    seed_z[i*8 +: 8] = parsed_val[7:0];
                end
                have_z = 1'b1;
            end

            if (have_d && have_z) begin
                kat_count = kat_count + 1;

                reset_dut();
                run_keygen_once(cyc_kg);
                build_test_message(kat_count);
                preload_encrypt_inputs();
                run_encrypt_once(cyc_enc);
                preload_decrypt_inputs();
                run_decrypt_once(cyc_dec);
                check_roundtrip(kat_count, err_count);

                if (err_count == 0) begin
                    $display("KAT #%0d roundtrip PASSED (cycles: keygen=%0d, enc=%0d, dec=%0d, total=%0d)",
                             kat_count, cyc_kg, cyc_enc, cyc_dec, (cyc_kg + cyc_enc + cyc_dec));
                end else begin
                    $display("KAT #%0d roundtrip has cumulative errors=%0d", kat_count, err_count);
                end

                have_d = 1'b0;
                have_z = 1'b0;

                if (kat_count >= max_kats) begin
                    $display("Reached MAX_KATS=%0d, stopping.", max_kats);
                    break;
                end
            end
        end

        $fclose(fd);

        if (err_count == 0) begin
            $display("ALL ROUNDTRIP TESTS PASSED: %0d vectors", kat_count);
        end else begin
            $display("ROUNDTRIP TEST FAILED: %0d mismatches across %0d vectors", err_count, kat_count);
            $fatal(1);
        end
        $finish;
    end

endmodule
