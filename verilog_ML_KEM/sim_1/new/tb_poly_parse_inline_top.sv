`timescale 1ns / 1ps

module tb_poly_parse_inline_top();

    // =========================================================
    // 1. SIGNAL DECLARATIONS
    // =========================================================
    logic         clk;
    logic         rst_n;
    logic         start;
    logic         done;

    // Simulated Keccak Stream Interface
    logic [7:0]   shake_dout;
    logic         shake_dout_valid;
    logic         shake_dout_ready;

    // RAM Output Interface
    logic         ram_we_a0;
    logic         ram_we_a1;
    logic [6:0]   ram_addr;
    logic [15:0]  ram_a0_din;
    logic [15:0]  ram_a1_din;

    // =========================================================
    // 2. DEVICE UNDER TEST (DUT)
    // =========================================================
    poly_parse_inline_top dut (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .done(done),
        .shake_dout(shake_dout),
        .shake_dout_valid(shake_dout_valid),
        .shake_dout_ready(shake_dout_ready),
        .ram_we_a0(ram_we_a0),
        .ram_we_a1(ram_we_a1),
        .ram_addr(ram_addr),
        .ram_a0_din(ram_a0_din),
        .ram_a1_din(ram_a1_din)
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
    // 4. MOCK KECCAK STREAM GENERATOR (WITH BACKPRESSURE)
    // =========================================================
    // Khối này đóng vai trò như lõi SHAKE128
    // Nó liên tục ném byte ra (shake_dout_valid = 1)
    // Nhưng nếu Parse chưa sẵn sàng (shake_dout_ready = 0), nó phải giữ nguyên byte đó
    always @(posedge clk) begin
        if (!rst_n) begin
            shake_dout       <= 0;
            shake_dout_valid <= 0;
        end else if (is_running && !done) begin
            shake_dout_valid <= 1;
            // Chỉ tạo byte ngẫu nhiên mới nếu khối Parse ĐÃ NHẬN byte cũ
            if (shake_dout_ready) begin
                shake_dout <= $urandom_range(0, 255);
            end
        end else begin
            shake_dout_valid <= 0;
        end
    end

    // =========================================================
    // 5. ON-THE-FLY VERIFICATION
    // =========================================================
    integer valid_coeff_written = 0;

    always @(posedge clk) begin
        if (rst_n && is_running) begin
            if (ram_we_a0) begin
                valid_coeff_written++;
                if (ram_a0_din >= 16'd3329) begin
                    $display("   [FATAL ERROR] Rejection Failed! A0 wrote %0d (>= 3329)", ram_a0_din);
                    $finish;
                end
            end
            
            if (ram_we_a1) begin
                valid_coeff_written++;
                if (ram_a1_din >= 16'd3329) begin
                    $display("   [FATAL ERROR] Rejection Failed! A1 wrote %0d (>= 3329)", ram_a1_din);
                    $finish;
                end
            end
        end
    end

    // =========================================================
    // 6. TEST SEQUENCE
    // =========================================================
    integer tc;
    
    initial begin
        clk   = 0;
        rst_n = 0;
        start = 0;

        $display("=================================================");
        $display("   STARTING BATCH TEST: POLY PARSE (INLINE)      ");
        $display("=================================================");

        #20;
        rst_n = 1;
        #10;

        // Run 5 testcases
        for (tc = 1; tc <= 5; tc++) begin
            $display("-------------------------------------------------");
            $display(">> RUNNING TESTCASE %0d / 5", tc);
            
            valid_coeff_written = 0;

            @(negedge clk);
            start = 1;
            @(negedge clk);
            start = 0;

            wait(done);
            @(posedge clk);

            if (valid_coeff_written == 256) begin
                $display(">> [SUCCESS] Exactly 256 valid coefficients written.");
                $display("   [PERFORMANCE] Completed in %0d clock cycles. (Non-deterministic: varies by reject rate)", cycle_count);
            end else begin
                $display(">> [FAILED] Expected 256 coefficients, but wrote %0d.", valid_coeff_written);
                $finish;
            end
        end

        $display("=================================================");
        $display("   ALL 5 TESTCASES PASSED! SIMULATION COMPLETED  ");
        $display("=================================================");
        #50;
        $finish;
    end

endmodule