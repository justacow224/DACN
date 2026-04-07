`timescale 1ns / 1ps

module tb_butterfly();

    // Khai báo các tín hiệu kết nối
    reg         clk;
    reg         rst_n;
    reg         en;
    
    reg  [15:0] a;
    reg  [15:0] b;
    reg  [15:0] zeta;
    
    wire [15:0] a_prime;
    wire [15:0] b_prime;

    // Khởi tạo Module (DUT - Device Under Test)
    ntt_butterfly dut (
        .clk(clk),
        .rst_n(rst_n),
        .en(en),
        .a(a),
        .b(b),
        .zeta(zeta),
        .a_prime(a_prime),
        .b_prime(b_prime)
    );

    // Tạo xung clock (Chu kỳ 10ns -> Tần số 100MHz)
    always #5 clk = ~clk;

    // Tiến trình nạp dữ liệu (Stimulus)
    integer errors = 0;

    initial begin
        // 1. Khởi tạo trạng thái ban đầu
        clk   = 0;
        rst_n = 0;
        en    = 0;
        a     = 0;
        b     = 0;
        zeta  = 0;

        $display("=================================================");
        $display("   BAT DAU MO PHONG PIPELINE KHOSI BUTTERFLY     ");
        $display("=================================================");

        // Chờ 20ns rồi nhả Reset
        #20;
        rst_n = 1;
        
        // Bật Enable để ống nước hoạt động
        @(negedge clk);
        en = 1;

        // ---------------------------------------------------------
        // NHỊP CLOCK 1: Bơm Test Vector 1
        // Toán học: t = (2000 * 1729) % 3329 = 2498
        //           a' = (1000 + 2498) % 3329 = 169
        //           b' = (1000 - 2498) % 3329 = 1831
        // ---------------------------------------------------------
        a = 16'd1000; b = 16'd2000; zeta = 16'd1729;
        
        // ---------------------------------------------------------
        // NHỊP CLOCK 2: Bơm Test Vector 2 (Cạnh biên lớn nhất)
        // Toán học: t = (3328 * 1) % 3329 = 3328
        //           a' = (3328 + 3328) % 3329 = 3327
        //           b' = (3328 - 3328) % 3329 = 0
        // ---------------------------------------------------------
        @(negedge clk);
        a = 16'd3328; b = 16'd3328; zeta = 16'd1;

        // ---------------------------------------------------------
        // NHỊP CLOCK 3: Bơm Test Vector 3 (Cạnh biên nhỏ nhất)
        // Toán học: t = (1 * 1729) % 3329 = 1729
        //           a' = (0 + 1729) % 3329 = 1729
        //           b' = (0 - 1729) % 3329 = 1600
        // ---------------------------------------------------------
        @(negedge clk);
        a = 16'd0; b = 16'd1; zeta = 16'd1729;

        // ---------------------------------------------------------
        // NHỊP CLOCK 4: Tắt bơm dữ liệu, ngóng chờ kết quả
        // ---------------------------------------------------------
        @(negedge clk);
        a = 0; b = 0; zeta = 0; 
        en = 1; // Vẫn phải giữ Enable để dữ liệu cũ trôi tiếp trong ống

        // Đợi kết quả của Test 1 trào ra (Mất đúng 5 chu kỳ từ lúc bơm)
        @(negedge clk); // Clock 5
        @(negedge clk); // Clock 6 -> Kết quả Test 1 xuất hiện
        $display("[TEST 1] a'= %0d (Chuan: 169)  | b'= %0d (Chuan: 1831)", a_prime, b_prime);
        if (a_prime !== 16'd169 || b_prime !== 16'd1831) begin
            $display("   -> [ERROR] Test 1 Failed!");
            errors = errors + 1;
        end

        // Chu kỳ tiếp theo là kết quả của Test 2
        @(negedge clk); // Clock 7
        $display("[TEST 2] a'= %0d (Chuan: 3327) | b'= %0d (Chuan: 0)", a_prime, b_prime);
        if (a_prime !== 16'd3327 || b_prime !== 16'd0) begin
            $display("   -> [ERROR] Test 2 Failed!");
            errors = errors + 1;
        end

        // Chu kỳ tiếp theo là kết quả của Test 3
        @(negedge clk); // Clock 8
        $display("[TEST 3] a'= %0d (Chuan: 1729) | b'= %0d (Chuan: 1600)", a_prime, b_prime);
        if (a_prime !== 16'd1729 || b_prime !== 16'd1600) begin
            $display("   -> [ERROR] Test 3 Failed!");
            errors = errors + 1;
        end

        $display("=================================================");
        if (errors == 0) begin
            $display(">> [SUCCESS] MO PHONG HOAN TAT - ALL PASSED! <<");
        end else begin
            $display(">> [FAILED] MO PHONG HOAN TAT - %0d ERRORS! <<", errors);
        end
        $display("=================================================");
        
        // Dừng mô phỏng
        #20;
        $finish;
    end

endmodule