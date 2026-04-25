`timescale 1ns / 1ps

module tb_kpke_core;
    localparam int DEFAULT_VECTORS       = 10;
    localparam int KEYGEN_TIMEOUT_CYCLES = 1200000;
    localparam int CORE_TIMEOUT_CYCLES   = 3000000;

    reg clk;
    reg rst_n;

    // KeyGen
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

    // Shared core
    reg         core_start;
    reg [1:0]   core_mode;
    wire        core_busy;
    wire        core_done;
    reg         core_in_we;
    reg [1:0]   core_in_sel;
    reg [10:0]  core_in_addr;
    reg [7:0]   core_in_wdata;
    wire [255:0] core_m_out;
    wire        core_ct_we;
    wire [10:0] core_ct_addr;
    wire [7:0]  core_ct_dout;

    reg [7:0] pk_mem [0:1183];
    reg [7:0] sk_mem [0:2399];
    reg [7:0] ct_mem [0:1087];
    reg [7:0] m_msg  [0:31];
    reg [7:0] r_msg  [0:31];

    integer i;
    integer vec_idx;
    integer max_vectors;
    integer wait_cycles;
    integer err_count;

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

    kpke_core dut (
        .clk(clk),
        .rst_n(rst_n),
        .start(core_start),
        .mode(core_mode),
        .busy(core_busy),
        .done(core_done),
        .in_we(core_in_we),
        .in_sel(core_in_sel),
        .in_addr(core_in_addr),
        .in_wdata(core_in_wdata),
        .m_out(core_m_out),
        .ct_we(core_ct_we),
        .ct_addr(core_ct_addr),
        .ct_dout(core_ct_dout),
        .k_init(),
        .k_hash_type(),
        .k_finalize(),
        .k_din(),
        .k_din_valid(),
        .k_din_ready(1'b0),
        .k_dout(8'd0),
        .k_dout_valid(1'b0),
        .k_dout_ready()
    );

    always #5 clk = ~clk;

    always @(posedge clk) begin
        if (pk_we && (pk_addr < 11'd1184)) begin
            pk_mem[pk_addr] <= pk_dout;
        end
        if (sk_we && (sk_addr < 12'd2400)) begin
            sk_mem[sk_addr] <= sk_dout;
        end
        if (core_ct_we && (core_ct_addr < 11'd1088)) begin
            ct_mem[core_ct_addr] <= core_ct_dout;
        end
    end

    task automatic reset_dut;
        begin
            rst_n         = 1'b0;
            kg_start      = 1'b0;
            seed_d        = 256'd0;
            seed_z        = 256'd0;
            core_start    = 1'b0;
            core_mode     = 2'd0;
            core_in_we    = 1'b0;
            core_in_sel   = 2'd0;
            core_in_addr  = 11'd0;
            core_in_wdata = 8'd0;
            repeat (4) @(posedge clk);
            rst_n = 1'b1;
            @(posedge clk);
        end
    endtask

    task automatic run_keygen_once;
        begin
            @(posedge clk);
            kg_start <= 1'b1;
            @(posedge clk);
            kg_start <= 1'b0;

            wait_cycles = 0;
            while (!kg_done && (wait_cycles < KEYGEN_TIMEOUT_CYCLES)) begin
                @(posedge clk);
                wait_cycles = wait_cycles + 1;
            end

            if (!kg_done) begin
                $display("ERROR: keygen timeout at vector %0d", vec_idx);
                $fatal(1);
            end
        end
    endtask

    task automatic run_core_once(input [1:0] mode);
        begin
            @(posedge clk);
            core_mode  <= mode;
            core_start <= 1'b1;
            @(posedge clk);
            core_start <= 1'b0;

            wait_cycles = 0;
            while (!core_done && (wait_cycles < CORE_TIMEOUT_CYCLES)) begin
                @(posedge clk);
                wait_cycles = wait_cycles + 1;
            end

            if (!core_done) begin
                $display("ERROR: core timeout at vector %0d mode=%0d", vec_idx, mode);
                $fatal(1);
            end
        end
    endtask

    task automatic preload_encrypt_inputs;
        begin
            core_mode <= 2'd1;
            for (i = 0; i < 1184; i = i + 1) begin
                core_in_we    <= 1'b1;
                core_in_sel   <= 2'd0;
                core_in_addr  <= i[10:0];
                core_in_wdata <= pk_mem[i];
                @(posedge clk);
            end
            for (i = 0; i < 32; i = i + 1) begin
                core_in_we    <= 1'b1;
                core_in_sel   <= 2'd1;
                core_in_addr  <= i[10:0];
                core_in_wdata <= m_msg[i];
                @(posedge clk);
            end
            for (i = 0; i < 32; i = i + 1) begin
                core_in_we    <= 1'b1;
                core_in_sel   <= 2'd2;
                core_in_addr  <= i[10:0];
                core_in_wdata <= r_msg[i];
                @(posedge clk);
            end
            core_in_we <= 1'b0;
        end
    endtask

    task automatic preload_decrypt_inputs;
        begin
            core_mode <= 2'd0;
            for (i = 0; i < 1152; i = i + 1) begin
                core_in_we    <= 1'b1;
                core_in_sel   <= 2'd0;
                core_in_addr  <= i[10:0];
                core_in_wdata <= sk_mem[i];
                @(posedge clk);
            end
            for (i = 0; i < 1088; i = i + 1) begin
                core_in_we    <= 1'b1;
                core_in_sel   <= 2'd1;
                core_in_addr  <= i[10:0];
                core_in_wdata <= ct_mem[i];
                @(posedge clk);
            end
            core_in_we <= 1'b0;
        end
    endtask

    initial begin
        clk = 1'b0;
        reset_dut();

        max_vectors = DEFAULT_VECTORS;
        if ($value$plusargs("MAX_VECTORS=%d", max_vectors)) begin
            $display("INFO: Override MAX_VECTORS=%0d", max_vectors);
        end

        err_count = 0;
        $display("===== kpke_core mode-switch regression =====");

        for (vec_idx = 0; vec_idx < max_vectors; vec_idx = vec_idx + 1) begin
            // Deterministic seeds and messages per vector.
            seed_d = {8{32'h0123_4567 ^ (vec_idx * 32'h0001_0001)}};
            seed_z = {8{32'h89AB_CDEF ^ (vec_idx * 32'h0000_1010)}};

            for (i = 0; i < 32; i = i + 1) begin
                m_msg[i] = (vec_idx * 8'h13) ^ (i * 8'h07) ^ 8'h5A;
                r_msg[i] = (vec_idx * 8'h09) ^ (i * 8'h21) ^ 8'hA5;
            end
            for (i = 0; i < 1088; i = i + 1) begin
                ct_mem[i] = 8'h00;
            end

            run_keygen_once();

            preload_encrypt_inputs();
            run_core_once(2'd1);

            preload_decrypt_inputs();
            run_core_once(2'd0);

            for (i = 0; i < 32; i = i + 1) begin
                if (core_m_out[i*8 +: 8] !== m_msg[i]) begin
                    $display("ERROR: vec %0d mismatch at m[%0d] exp=%02x got=%02x",
                             vec_idx, i, m_msg[i], core_m_out[i*8 +: 8]);
                    err_count = err_count + 1;
                end
            end

            if (err_count == 0) begin
                $display("vec %0d PASS (mode enc->dec)", vec_idx);
            end else begin
                $display("vec %0d cumulative errors=%0d", vec_idx, err_count);
            end
        end

        if (err_count == 0) begin
            $display("tb_kpke_core: PASS (%0d vectors)", max_vectors);
        end else begin
            $display("tb_kpke_core: FAIL errors=%0d", err_count);
            $fatal(1);
        end

        $finish;
    end

endmodule

