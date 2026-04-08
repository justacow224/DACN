`timescale 1ns / 1ps

module poly_tomsg_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    output reg          done,

    output reg  [6:0]   ram_addr,  
    input  wire [15:0]  ram_a0_dout,
    input  wire [15:0]  ram_a1_dout,

    // Output: 32 bytes = 4 words x 64-bit
    output reg          buf_we,
    output reg  [5:0]   buf_addr,   // 0 to 3
    output reg  [63:0]  buf_din
);

    localparam IDLE   = 2'd0;
    localparam PIPE   = 2'd1;
    localparam FINISH = 2'd2; 

    reg [1:0]   state;
    reg [7:0]   req_count;     
    reg [7:0]   process_count; 
    reg [1:0]   val_pipe;      

    reg [63:0]  shift_reg;     
    reg [6:0]   bit_count;
    reg [2:0]   out_word_count;

    // Chuẩn hóa và so sánh bằng Comparator (Mật khẩu d=1: Từ 833 đến 2496)
    wire signed [15:0] in0 = ram_a0_dout;
    wire signed [15:0] in1 = ram_a1_dout;

    wire [15:0] norm0 = (in0 < 0) ? (in0 + 16'd3329) : (in0 >= 16'd3329) ? (in0 - 16'd3329) : in0;
    wire [15:0] norm1 = (in1 < 0) ? (in1 + 16'd3329) : (in1 >= 16'd3329) ? (in1 - 16'd3329) : in1;

    wire bit0 = (norm0 >= 16'd833) && (norm0 <= 16'd2496);
    wire bit1 = (norm1 >= 16'd833) && (norm1 <= 16'd2496);

    wire [1:0] new_2b = {bit1, bit0};
    
    wire [63:0] merged_shift = shift_reg | ({62'd0, new_2b} << bit_count);
    wire write_trigger = (bit_count == 7'd62); // Đủ 64 bit (62 + 2)

    always @(posedge clk) begin
        if (!rst_n) begin
            state          <= IDLE;
            req_count      <= 0; process_count  <= 0; val_pipe <= 0;
            shift_reg      <= 0; bit_count      <= 0;
            ram_addr       <= 0; buf_we         <= 0; buf_addr <= 0;
            buf_din        <= 0; out_word_count <= 0; done     <= 0;
        end else begin
            buf_we <= 0; done <= 0;

            case (state)
                IDLE: begin
                    if (start) begin
                        req_count <= 0; process_count <= 0; val_pipe <= 0;
                        shift_reg <= 0; bit_count <= 0; out_word_count <= 0;
                        state <= PIPE;
                    end
                end

                PIPE: begin
                    if (req_count < 128) begin
                        ram_addr  <= req_count[6:0];
                        req_count <= req_count + 1;
                        val_pipe  <= {val_pipe[0], 1'b1};
                    end else begin
                        val_pipe  <= {val_pipe[0], 1'b0};
                    end

                    if (val_pipe[1]) begin
                        if (write_trigger) begin
                            buf_we   <= 1;
                            buf_din  <= merged_shift[63:0];
                            buf_addr <= out_word_count;
                            
                            out_word_count <= out_word_count + 1;
                            shift_reg      <= 0;
                            bit_count      <= 0;
                        end else begin
                            shift_reg <= merged_shift;
                            bit_count <= bit_count + 2;
                        end
                        
                        process_count <= process_count + 1;
                        
                        if (process_count == 127) begin
                            state <= FINISH;
                        end
                    end
                end
                
                FINISH: begin
                    state <= IDLE;
                    done  <= 1;
                end
            endcase
        end
    end
endmodule