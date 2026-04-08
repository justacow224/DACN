`timescale 1ns / 1ps

module poly_to_bytes_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    output reg          done,

    output reg  [6:0]   ram_addr,  
    input  wire [15:0]  ram_a0_dout,
    input  wire [15:0]  ram_a1_dout,

    output reg          buf_we,
    output reg  [5:0]   buf_addr,   
    output reg  [63:0]  buf_din
);

    // =================================================================
    // 1. FSM & PIPELINE REGISTERS
    // =================================================================
    localparam IDLE   = 2'd0;
    localparam PIPE   = 2'd1;
    localparam FINISH = 2'd2; // FIX: Thêm trạng thái chờ RAM ghi xong

    reg [1:0]   state; // Nâng cấp lên 2-bit
    reg [7:0]   req_count;     
    reg [7:0]   process_count; 
    reg [1:0]   val_pipe;      

    reg [103:0] shift_reg;     
    reg [7:0]   bit_count;
    
    reg [5:0]   out_word_count; 

    // =================================================================
    // 2. COMBINATIONAL LOGIC
    // =================================================================
    wire [23:0] new_24b = {ram_a1_dout[11:0], ram_a0_dout[11:0]};
    
    wire [103:0] merged_shift = shift_reg | ({80'd0, new_24b} << bit_count);
    wire [7:0]   next_bit_count = bit_count + 8'd24;
    
    wire write_trigger = (next_bit_count >= 64);

    // =================================================================
    // 3. MAIN PIPELINE
    // =================================================================
    always @(posedge clk) begin
        if (!rst_n) begin
            state          <= IDLE;
            req_count      <= 0;
            process_count  <= 0;
            val_pipe       <= 2'b00;
            shift_reg      <= 0;
            bit_count      <= 0;
            ram_addr       <= 0;
            buf_we         <= 0;
            buf_addr       <= 0;
            buf_din        <= 0;
            out_word_count <= 0;
            done           <= 0;
        end else begin
            buf_we <= 0;
            done   <= 0;

            case (state)
                IDLE: begin
                    if (start) begin
                        req_count      <= 0;
                        process_count  <= 0;
                        val_pipe       <= 2'b00;
                        shift_reg      <= 0;
                        bit_count      <= 0;
                        buf_addr       <= 0;
                        out_word_count <= 0;
                        state          <= PIPE;
                    end
                end

                PIPE: begin
                    // --- STAGE 1: REQUEST ---
                    if (req_count < 128) begin
                        ram_addr  <= req_count[6:0];
                        req_count <= req_count + 1;
                        val_pipe  <= {val_pipe[0], 1'b1};
                    end else begin
                        val_pipe  <= {val_pipe[0], 1'b0};
                    end

                    // --- STAGE 2 & 3: PROCESS & WRITE ---
                    if (val_pipe[1]) begin
                        if (write_trigger) begin
                            buf_we   <= 1;
                            buf_din  <= merged_shift[63:0];
                            
                            buf_addr       <= out_word_count;
                            out_word_count <= out_word_count + 1;
                            
                            shift_reg <= merged_shift >> 64;
                            bit_count <= next_bit_count - 64;
                        end else begin
                            shift_reg <= merged_shift;
                            bit_count <= next_bit_count;
                        end
                        
                        process_count <= process_count + 1;
                        
                        if (process_count == 127) begin
                            // FIX: Không báo done ngay, nhảy sang FINISH chờ 1 nhịp
                            state <= FINISH;
                        end
                    end
                end
                
                FINISH: begin
                    // Ở chu kỳ này, RAM đã nuốt trọn từ cuối cùng. An toàn để giật cờ done!
                    state <= IDLE;
                    done  <= 1;
                end
            endcase
        end
    end

endmodule