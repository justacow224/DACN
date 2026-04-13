`timescale 1ns / 1ps

module tb_ml_kem_keygen_wrapper;
    localparam int KEYGEN_TIMEOUT_CYCLES = 500000;

    reg clk;
    reg rst_n;

    reg        start;
    wire       busy;
    wire       done;

    reg        seed_we;
    reg        seed_sel;
    reg [4:0]  seed_addr;
    reg [7:0]  seed_wdata;

    reg        out_rd;
    reg        out_sel;
    reg [11:0] out_addr;
    wire [7:0] out_rdata;
    wire       out_valid;

    reg [255:0] seed_d;
    reg [255:0] seed_z;

    reg [7:0] pk_mem [0:1183];
    reg [7:0] sk_mem [0:2399];
    reg [7:0] expected_pk [0:1183];
    reg [7:0] expected_sk [0:2399];

    integer fd, status, i;
    string line;
    int data_val;
    int cycle_count;
    int kat_count;
    bit have_d, have_z, have_pk, have_sk;

    ml_kem_keygen_io_wrapper dut (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .busy(busy),
        .done(done),
        .seed_we(seed_we),
        .seed_sel(seed_sel),
        .seed_addr(seed_addr),
        .seed_wdata(seed_wdata),
        .out_rd(out_rd),
        .out_sel(out_sel),
        .out_addr(out_addr),
        .out_rdata(out_rdata),
        .out_valid(out_valid)
    );

    always #5 clk = ~clk;

    function int hex_char_to_val(input byte c);
        if (c >= "0" && c <= "9") return c - "0";
        if (c >= "a" && c <= "f") return c - "a" + 10;
        if (c >= "A" && c <= "F") return c - "A" + 10;
        return 0;
    endfunction

    task automatic reset_dut();
        begin
            rst_n = 0;
            start = 0;
            seed_we = 0;
            seed_sel = 0;
            seed_addr = 0;
            seed_wdata = 0;
            out_rd = 0;
            out_sel = 0;
            out_addr = 0;
            repeat (3) @(posedge clk);
            rst_n = 1;
            repeat (2) @(posedge clk);
        end
    endtask

    task automatic write_seed(input bit sel, input [255:0] seed_bits);
        integer t;
        begin
            for (t = 0; t < 32; t = t + 1) begin
                @(posedge clk);
                seed_we <= 1;
                seed_sel <= sel;
                seed_addr <= t[4:0];
                seed_wdata <= seed_bits[t*8 +: 8];
            end
            @(posedge clk);
            seed_we <= 0;
        end
    endtask

    task automatic run_keygen_with_timeout(output int cycles_out);
        int watchdog;
        begin
            @(posedge clk);
            start <= 1;
            @(posedge clk);
            start <= 0;

            cycles_out = 0;
            watchdog = 0;
            while (!done && watchdog < KEYGEN_TIMEOUT_CYCLES) begin
                @(posedge clk);
                cycles_out++;
                watchdog++;
            end

            if (!done) begin
                $display("ERROR: Timeout waiting done");
                $fatal(1);
            end
        end
    endtask

    task automatic read_pk_sk_outputs();
        integer t;
        begin
            for (t = 0; t < 1184; t = t + 1) begin
                @(posedge clk);
                out_sel <= 0;
                out_addr <= t[11:0];
                out_rd <= 1;
                @(posedge clk);
                out_rd <= 0;
                #1;
                if (!out_valid) begin
                    $display("ERROR: pk out_valid low at byte %0d", t);
                    $fatal(1);
                end
                pk_mem[t] = out_rdata;
            end

            for (t = 0; t < 2400; t = t + 1) begin
                @(posedge clk);
                out_sel <= 1;
                out_addr <= t[11:0];
                out_rd <= 1;
                @(posedge clk);
                out_rd <= 0;
                #1;
                if (!out_valid) begin
                    $display("ERROR: sk out_valid low at byte %0d", t);
                    $fatal(1);
                end
                sk_mem[t] = out_rdata;
            end
        end
    endtask

    initial begin
        clk = 0;
        reset_dut();

        fd = $fopen("D:/HCMUT/Year_4/252/CA/Source/DACN/vitis_ML_KEM/src/KAT_768.txt", "r");
        if (fd == 0) begin
            $display("ERROR: Cannot open KAT file");
            $finish;
        end

        kat_count = 0;
        have_d = 0;
        have_z = 0;
        have_pk = 0;
        have_sk = 0;

        while (!$feof(fd)) begin
            status = $fgets(line, fd);
            if (line.substr(0, 3) == "d = ") begin
                for (i = 0; i < 32; i++) begin
                    data_val = (hex_char_to_val(line[4 + i*2]) << 4) | hex_char_to_val(line[4 + i*2 + 1]);
                    seed_d[i*8 +: 8] = data_val[7:0];
                end
                have_d = 1;
            end else if (line.substr(0, 3) == "z = ") begin
                for (i = 0; i < 32; i++) begin
                    data_val = (hex_char_to_val(line[4 + i*2]) << 4) | hex_char_to_val(line[4 + i*2 + 1]);
                    seed_z[i*8 +: 8] = data_val[7:0];
                end
                have_z = 1;
            end else if (line.substr(0, 4) == "pk = ") begin
                for (i = 0; i < 1184; i++) begin
                    expected_pk[i] = (hex_char_to_val(line[5 + i*2]) << 4) | hex_char_to_val(line[5 + i*2 + 1]);
                end
                have_pk = 1;
            end else if (line.substr(0, 4) == "sk = ") begin
                for (i = 0; i < 2400; i++) begin
                    expected_sk[i] = (hex_char_to_val(line[5 + i*2]) << 4) | hex_char_to_val(line[5 + i*2 + 1]);
                end
                have_sk = 1;

                if (!(have_d && have_z && have_pk && have_sk)) begin
                    $display("ERROR: Incomplete KAT vector %0d", kat_count);
                    $fatal(1);
                end

                kat_count = kat_count + 1;
                reset_dut();
                write_seed(1'b0, seed_d);
                write_seed(1'b1, seed_z);
                run_keygen_with_timeout(cycle_count);
                read_pk_sk_outputs();

                for (i = 0; i < 1184; i++) begin
                    if (pk_mem[i] !== expected_pk[i]) begin
                        $display("PK mismatch (wrapper) at byte %0d exp=%02x got=%02x", i, expected_pk[i], pk_mem[i]);
                        $fatal(1);
                    end
                end

                for (i = 0; i < 2400; i++) begin
                    if (sk_mem[i] !== expected_sk[i]) begin
                        $display("SK mismatch (wrapper) at byte %0d exp=%02x got=%02x", i, expected_sk[i], sk_mem[i]);
                        $fatal(1);
                    end
                end

                $display("Wrapper KAT #%0d PASSED (%0d cycles)", kat_count, cycle_count);

                have_d = 0;
                have_z = 0;
                have_pk = 0;
                have_sk = 0;
            end
        end

        $fclose(fd);
        $display("ALL WRAPPER KAT PASSED: %0d vectors", kat_count);
        $finish;
    end

endmodule
