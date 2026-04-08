`timescale 1ns / 1ps

module poly_decompress_v_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    output reg          done,

    // Input Buffer Interface
    // 128 bytes = 16 words of 64-bit
    output reg  [5:0]   buf_addr,  // 0 to 15
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
    reg [5:0]   req_count;     // Trình nạp: 0 to 16
    reg [6:0]   process_count; // Trình xử lý: 0 to 127
    
    reg [1:0]   fetch_valid_pipe; 
    reg [127:0] shift_reg;        
    reg [7:0]   bit_count;

    // =================================================================
    // 2. LOGIC ĐIỀU PHỐI ĐƯỜNG ỐNG
    // =================================================================
    wire data_arriving = fetch_valid_pipe[1];
    
    wire [127:0] new_data = {64'd0, buf_dout};
    wire [127:0] combined_data = shift_reg | (data_arriving ? (new_data << bit_count) : 128'd0);
    
    wire [7:0] current_bits = bit_count + (data_arriving ? 8'd64 : 8'd0);
    
    // Decompress V chỉ cần nhai 8 bit (1 byte) mỗi chu kỳ
    wire can_process = (current_bits >= 8) && (state == RUN);
    
    wire [7:0] next_bit_count = current_bits - (can_process ? 8'd8 : 8'd0);
    
    wire issue_fetch = (next_bit_count < 8'd64) && (req_count < 16) && (fetch_valid_pipe == 2'b00) && (state == RUN);

    // =================================================================
    // 3. LÕI TOÁN HỌC TỐI GIẢN (MATH CORE 16-BIT)
    // =================================================================
    wire [7:0] current_byte = combined_data[7:0];
    wire [3:0] v0 = current_byte[3:0];
    wire [3:0] v1 = current_byte[7:4];

    // Mọi tính toán nằm trọn vẹn trong 16-bit (Max = 49943 < 65535)
    wire [15:0] val0 = ({12'd0, v0} * 16'd3329 + 16'd8) >> 4;
    wire [15:0] val1 = ({12'd0, v1} * 16'd3329 + 16'd8) >> 4;

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
                    // --- MẠCH NẠP ---
                    if (issue_fetch) begin
                        buf_addr <= req_count;
                        req_count <= req_count + 1;
                        fetch_valid_pipe <= {fetch_valid_pipe[0], 1'b1};
                    end else begin
                        fetch_valid_pipe <= {fetch_valid_pipe[0], 1'b0};
                    end

                    // --- MẠCH TIÊU THỤ ---
                    if (can_process) begin
                        ram_we_a0 <= 1;
                        ram_we_a1 <= 1;
                        ram_addr  <= process_count;
                        ram_a0_din <= val0;
                        ram_a1_din <= val1;

                        process_count <= process_count + 1;
                        if (process_count == 127) begin
                            state <= IDLE;
                            done  <= 1;
                        end
                    end
                    
                    // --- CẬP NHẬT BỘ ĐỆM ---
                    shift_reg <= can_process ? (combined_data >> 8) : combined_data;
                    bit_count <= next_bit_count;
                end
            endcase
        end
    end

endmodule