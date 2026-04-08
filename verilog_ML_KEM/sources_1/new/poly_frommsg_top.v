`timescale 1ns / 1ps

module poly_frommsg_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    output reg          done,

    // Input: 32 bytes = 4 words x 64-bit
    output reg  [5:0]   buf_addr,  // 0 to 3
    input  wire [63:0]  buf_dout,

    output reg          ram_we_a0,
    output reg          ram_we_a1,
    output reg  [6:0]   ram_addr,  // 0 to 127
    output reg  [15:0]  ram_a0_din,
    output reg  [15:0]  ram_a1_din
);

    localparam IDLE = 1'b0;
    localparam RUN  = 1'b1;

    reg         state;
    reg [2:0]   req_count;     // 0 to 4
    reg [6:0]   process_count; // 0 to 127
    
    reg [1:0]   fetch_valid_pipe; 
    reg [127:0] shift_reg;        
    reg [7:0]   bit_count;

    wire data_arriving = fetch_valid_pipe[1];
    
    wire [127:0] new_data = {64'd0, buf_dout};
    wire [127:0] combined_data = shift_reg | (data_arriving ? (new_data << bit_count) : 128'd0);
    
    wire [7:0] current_bits = bit_count + (data_arriving ? 8'd64 : 8'd0);
    
    // Mối chu kỳ cắn 2 bit
    wire can_process = (current_bits >= 2) && (state == RUN);
    wire [7:0] next_bit_count = current_bits - (can_process ? 8'd2 : 8'd0);
    
    // Xin nạp thêm khi sắp cạn (< 64 bit) và chưa xin đủ 4 words
    wire issue_fetch = (next_bit_count < 8'd64) && (req_count < 4) && (fetch_valid_pipe == 2'b00) && (state == RUN);

    // Lõi quy đổi bit -> hệ số
    wire [1:0] curr_2bits = combined_data[1:0];
    wire [15:0] val0 = curr_2bits[0] ? 16'd1665 : 16'd0;
    wire [15:0] val1 = curr_2bits[1] ? 16'd1665 : 16'd0;

    always @(posedge clk) begin
        if (!rst_n) begin
            state <= IDLE;
            req_count <= 0; process_count <= 0; fetch_valid_pipe <= 0;
            shift_reg <= 0; bit_count <= 0; buf_addr <= 0;
            ram_we_a0 <= 0; ram_we_a1 <= 0; ram_addr <= 0;
            ram_a0_din <= 0; ram_a1_din <= 0; done <= 0;
        end else begin
            ram_we_a0 <= 0; ram_we_a1 <= 0; done <= 0;

            case (state)
                IDLE: begin
                    if (start) begin
                        req_count <= 0; process_count <= 0; fetch_valid_pipe <= 0;
                        shift_reg <= 0; bit_count <= 0; state <= RUN;
                    end
                end

                RUN: begin
                    if (issue_fetch) begin
                        buf_addr <= req_count;
                        req_count <= req_count + 1;
                        fetch_valid_pipe <= {fetch_valid_pipe[0], 1'b1};
                    end else begin
                        fetch_valid_pipe <= {fetch_valid_pipe[0], 1'b0};
                    end

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
                    
                    shift_reg <= can_process ? (combined_data >> 2) : combined_data;
                    bit_count <= next_bit_count;
                end
            endcase
        end
    end
endmodule