`timescale 1ns / 1ps

module poly_decompress_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    output reg          done,

    // Input Buffer Interface (Reads 64-bit words)
    // 320 bytes = 40 words of 64-bit
    output reg  [5:0]   buf_addr,  // 0 to 39
    input  wire [63:0]  buf_dout,

    // Output RAM Interface (Dual-port to write 2 coeffs at once)
    output reg          ram_we_a0,
    output reg          ram_we_a1,
    output reg  [6:0]   ram_addr,  // 0 to 127
    output reg  [15:0]  ram_a0_din,
    output reg  [15:0]  ram_a1_din
);

    // =================================================================
    // 1. FSM & PIPELINE REGISTERS
    // =================================================================
    localparam IDLE = 1'b0;
    localparam RUN  = 1'b1;

    reg         state;
    reg [5:0]   req_count;     // Trình nạp: 0 to 40 words
    reg [6:0]   process_count; // Trình tiêu thụ: 0 to 128 loops
    
    reg [1:0]   fetch_valid_pipe; // Theo dõi độ trễ 2 nhịp của RAM Buffer
    reg [127:0] shift_reg;        // Đệm khổng lồ chứa dữ liệu
    reg [7:0]   bit_count;

    // =================================================================
    // 2. LOGIC ĐIỀU PHỐI ĐƯỜNG ỐNG (PIPELINE CONTROL)
    // =================================================================
    wire data_arriving = fetch_valid_pipe[1];
    
    // Ghép dữ liệu mới (nếu có) vào bộ đệm hiện tại
    wire [127:0] new_data = {64'd0, buf_dout};
    wire [127:0] combined_data = shift_reg | (data_arriving ? (new_data << bit_count) : 128'd0);
    
    // Tính toán số bit hiện có
    wire [7:0] current_bits = bit_count + (data_arriving ? 8'd64 : 8'd0);
    
    // Chỉ xử lý khi có đủ 20 bit (2 hệ số) và đang chạy
    wire can_process = (current_bits >= 20) && (state == RUN);
    
    // Số bit còn lại sau khi đã cắn 20 bit
    wire [7:0] next_bit_count = current_bits - (can_process ? 8'd20 : 8'd0);
    
    // Logic xin thêm dữ liệu: Chỉ xin khi sắp cạn (< 64 bit) và chưa xin quá 40 words
    wire issue_fetch = (next_bit_count < 8'd64) && (req_count < 40) && (fetch_valid_pipe == 2'b00) && (state == RUN);

    // =================================================================
    // 3. LÕI TOÁN HỌC (MATH CORE)
    // =================================================================
    // Cắt trực tiếp 10 bit từ bộ đệm (Không cần dịch byte phức tạp)
    wire [9:0] u0 = combined_data[9:0];
    wire [9:0] u1 = combined_data[19:10];

    // val = (u * 3329 + 512) >> 10
    wire [31:0] val0 = ({22'd0, u0} * 32'd3329 + 32'd512) >> 10;
    wire [31:0] val1 = ({22'd0, u1} * 32'd3329 + 32'd512) >> 10;

    // =================================================================
    // 4. MAIN PIPELINE
    // =================================================================
    always @(posedge clk) begin
        if (!rst_n) begin
            state <= IDLE;
            req_count <= 0;
            process_count <= 0;
            fetch_valid_pipe <= 0;
            shift_reg <= 0;
            bit_count <= 0;
            buf_addr <= 0;
            ram_we_a0 <= 0;
            ram_we_a1 <= 0;
            ram_addr <= 0;
            ram_a0_din <= 0;
            ram_a1_din <= 0;
            done <= 0;
        end else begin
            ram_we_a0 <= 0;
            ram_we_a1 <= 0;
            done <= 0;

            case (state)
                IDLE: begin
                    if (start) begin
                        req_count <= 0;
                        process_count <= 0;
                        fetch_valid_pipe <= 0;
                        shift_reg <= 0;
                        bit_count <= 0;
                        state <= RUN;
                    end
                end

                RUN: begin
                    // --- MẠCH NẠP (FETCHER) ---
                    if (issue_fetch) begin
                        buf_addr <= req_count;
                        req_count <= req_count + 1;
                        fetch_valid_pipe <= {fetch_valid_pipe[0], 1'b1};
                    end else begin
                        fetch_valid_pipe <= {fetch_valid_pipe[0], 1'b0};
                    end

                    // --- MẠCH TIÊU THỤ (CONSUMER) ---
                    if (can_process) begin
                        ram_we_a0 <= 1;
                        ram_we_a1 <= 1;
                        ram_addr  <= process_count;
                        ram_a0_din <= val0[15:0];
                        ram_a1_din <= val1[15:0];

                        process_count <= process_count + 1;
                        if (process_count == 127) begin
                            state <= IDLE;
                            done  <= 1;
                        end
                    end
                    
                    // --- CẬP NHẬT BỘ ĐỆM ---
                    // Cắt bỏ 20 bit đã xử lý và giữ lại phần còn lại
                    shift_reg <= can_process ? (combined_data >> 20) : combined_data;
                    bit_count <= next_bit_count;
                end
            endcase
        end
    end

endmodule