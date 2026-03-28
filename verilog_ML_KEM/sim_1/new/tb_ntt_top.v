`timescale 1ns / 1ps

module tb_ntt_top();

    // =========================================================
    // 1. KHAI BÁO TÍN HIỆU
    // =========================================================
    reg         clk;
    reg         rst_n;
    reg         start;
    wire        done;

    reg         host_we;
    reg  [7:0]  host_addr;
    reg  [15:0] host_din;
    wire [15:0] host_dout;

    // =========================================================
    // 2. KHỞI TẠO MODULE CẦN TEST (DUT)
    // =========================================================
    ntt_top dut (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .done(done),
        .host_we(host_we),
        .host_addr(host_addr),
        .host_din(host_din),
        .host_dout(host_dout)
    );

    // =========================================================
    // 3. TẠO XUNG CLOCK (100MHz)
    // =========================================================
    always #5 clk = ~clk;

    // =========================================================
    // 4. BỘ ĐẾM CHU KỲ (PERFORMANCE COUNTER)
    // =========================================================
    integer cycle_count = 0;
    reg counting = 0;

    always @(posedge clk) begin
        if (start) counting <= 1;
        else if (done) counting <= 0;
        
        if (counting && !done) cycle_count <= cycle_count + 1;
    end

    // =========================================================
    // 5. KỊCH BẢN TEST (TEST SCENARIO)
    // =========================================================
    integer i;

    initial begin
        // Khởi tạo trạng thái ban đầu
        clk       = 0;
        rst_n     = 0;
        start     = 0;
        host_we   = 0;
        host_addr = 0;
        host_din  = 0;

        $display("=================================================");
        $display("    BAT DAU MO PHONG NTT TOP-LEVEL (ML-KEM)      ");
        $display("=================================================");

        // Reset hệ thống
        #20;
        rst_n = 1;
        #10;

        // ---------------------------------------------------------
        // BƯỚC 1: NẠP DỮ LIỆU VÀO RAM TỪ HOST
        // (Nạp thử các giá trị từ 0 đến 255 vào mảng)
        // ---------------------------------------------------------
        $display(">> Dang nap 256 he so vao BRAM...");
        for (i = 0; i < 256; i = i + 1) begin
            @(negedge clk);
            host_we   = 1;
            host_addr = i;
            host_din  = i; // Giả lập dữ liệu đầu vào chính là chỉ số index
        end
        @(negedge clk);
        host_we = 0; // Tắt cờ ghi

        // ---------------------------------------------------------
        // BƯỚC 2: KÍCH HOẠT NTT CHẠY
        // ---------------------------------------------------------
        $display(">> Phat tin hieu START. Dang cho NTT xu ly...");
        @(negedge clk);
        start = 1;
        @(negedge clk);
        start = 0;

        // ---------------------------------------------------------
        // BƯỚC 3: ĐỢI TÍN HIỆU DONE VÀ BÁO CÁO THỜI GIAN
        // ---------------------------------------------------------
        wait(done);
        @(negedge clk);
        $display(">> [THANH CONG] Tin hieu DONE da duoc bat!");
        $display(">> [HIEU NANG] Tong so chu ky clock de chay xong NTT: %0d cycles", cycle_count);
        $display("-------------------------------------------------");

        // ---------------------------------------------------------
        // BƯỚC 4: ĐỌC DỮ LIỆU TỪ RAM RA ĐỂ KIỂM TRA
        // ---------------------------------------------------------
        $display(">> XUAT KET QUA 16 HE SO DAU TIEN:");
        
        for (i = 0; i < 16; i = i + 1) begin
            @(negedge clk);
            host_addr = i; // Đưa địa chỉ vào
            
            @(negedge clk); // Đợi 1 chu kỳ để RAM đọc dữ liệu ra
            $display("   poly[%0d] = %0d", i, host_dout);
        end

        $display("=================================================");
        $display("              MO PHONG HOAN TAT                  ");
        $display("=================================================");
        
        #50;
        $finish;
    end

endmodule