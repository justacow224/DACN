`timescale 1ns / 1ps

module mul_mod (
    input  wire         clk,
    input  wire         rst_n, 
    input  wire         en,
    input  wire [15:0]  a,
    input  wire [15:0]  b,
    output reg  [15:0]  res
);

    // Hằng số được gọt lại theo giới hạn bit nhỏ nhất
    localparam [11:0] KYBER_Q   = 12'd3329;
    localparam [14:0] BARRETT_V = 15'd20159;

    // =========================================================
    // STAGE 1: TÍNH TÍCH P = a * b
    // Đầu vào Kyber <= 3328 (12-bit). 
    // P tối đa = 3328^2 = 11,075,584 -> Cần 24-bit là đủ.
    // =========================================================
    reg [23:0] P;
    always @(posedge clk) begin
        // Chỉ lấy 12 bit để nhân, tiết kiệm DSP
        if (en) P <= a[11:0] * b[11:0];
    end

    // =========================================================
    // STAGE 2: NHÂN BARRETT LẤY THƯƠNG SỐ
    // T_full = 24-bit * 15-bit = 39-bit
    // =========================================================
    reg [38:0] T_full;
    reg [23:0] P_delay1;
    always @(posedge clk) begin
        if (en) begin
            T_full   <= P * BARRETT_V;
            P_delay1 <= P;
        end
    end

    // =========================================================
    // STAGE 3: TÍNH t * Q
    // Thương số t = T_full >> 26.
    // T_full >> 26 đối với 39-bit chính là lấy các bit [38:26].
    // Vì t max = 3328, nên t lọt vừa vặn trong 12-bit [37:26].
    // =========================================================
    reg [23:0] P_delay2;
    reg [23:0] t_wire;
    always @(posedge clk) begin
        if (en) begin
            P_delay2 <= P_delay1;
            t_wire   <= T_full[37:26] * KYBER_Q;
        end
    end

    // =========================================================
    // STAGE 4: HIỆU CHỈNH MODULO (TỐI ƯU HÓA TOÁN HỌC)
    // - Lược bỏ hoàn toàn nhánh R >= 3329 (Dead code).
    // - Chỉ dùng toán tử 16-bit ở bước cuối cùng vì biết chắc 
    //   đáp án phải lọt vào [0, 3328].
    // =========================================================
    always @(posedge clk) begin
        if (!rst_n) begin
            res <= 16'd0;
        end else if (en) begin
            // Vẫn phải so sánh trên 24-bit để biết chính xác có bị âm hay không
            if (P_delay2 < t_wire) begin
                // Nếu Underflow, tính: phần dư + Q
                // Sử dụng toán học 16-bit giúp Vivado cắt bỏ bộ cộng 24-bit cồng kềnh
                res <= P_delay2[15:0] + 16'd3329 - t_wire[15:0];
            end else begin
                // Nhánh Normal
                res <= P_delay2[15:0] - t_wire[15:0];
            end
        end
    end

endmodule