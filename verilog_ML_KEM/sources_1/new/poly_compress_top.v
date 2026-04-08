`timescale 1ns / 1ps

module poly_compress_top (
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
    localparam FINISH = 2'd2; 

    reg [1:0]   state;
    reg [7:0]   req_count;     
    reg [7:0]   process_count; 
    reg [1:0]   val_pipe;      

    reg [9:0]   u0_reg, u1_reg;

    reg [103:0] shift_reg;     
    reg [7:0]   bit_count;
    reg [5:0]   out_word_count;

    // =================================================================
    // 2. MATH CORE: NORMALIZE & MAGIC MULTIPLIER (100% Precise)
    // =================================================================
    wire signed [15:0] in0 = ram_a0_dout;
    wire signed [15:0] in1 = ram_a1_dout;

    // Normalize: Đưa về dải [0, 3328]
    wire [15:0] norm0 = (in0 < 0) ? (in0 + 16'd3329) : (in0 >= 16'd3329) ? (in0 - 16'd3329) : in0;
    wire [15:0] norm1 = (in1 < 0) ? (in1 + 16'd3329) : (in1 >= 16'd3329) ? (in1 - 16'd3329) : in1;

    wire [31:0] t0 = ({16'd0, norm0} << 10) + 32'd1664;
    wire [31:0] t1 = ({16'd0, norm1} << 10) + 32'd1664;

    // FIX: Nâng cấp Magic Multiplier lên độ phân giải 33-bit để chính xác tuyệt đối
    wire [63:0] prod0 = t0 * 64'd2580335;
    wire [63:0] prod1 = t1 * 64'd2580335;

    // Thay vì >> 26, bây giờ ta >> 33
    wire [9:0] u_curr_0 = (prod0 >> 33) & 10'h3FF;
    wire [9:0] u_curr_1 = (prod1 >> 33) & 10'h3FF;

    // =================================================================
    // 3. PACKING LOGIC
    // =================================================================
    wire [39:0] new_40b = {u_curr_1, u_curr_0, u1_reg, u0_reg};
    
    wire [103:0] merged_shift = shift_reg | ({64'd0, new_40b} << bit_count);
    wire [7:0]   next_bit_count = bit_count + 8'd40;
    
    wire write_trigger = (next_bit_count >= 64);

    // =================================================================
    // 4. MAIN PIPELINE
    // =================================================================
    always @(posedge clk) begin
        if (!rst_n) begin
            state          <= IDLE;
            req_count      <= 0;
            process_count  <= 0;
            val_pipe       <= 2'b00;
            u0_reg         <= 0; u1_reg <= 0;
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
                    if (req_count < 128) begin
                        ram_addr  <= req_count[6:0];
                        req_count <= req_count + 1;
                        val_pipe  <= {val_pipe[0], 1'b1};
                    end else begin
                        val_pipe  <= {val_pipe[0], 1'b0};
                    end

                    if (val_pipe[1]) begin
                        if (process_count[0] == 1'b0) begin
                            u0_reg <= u_curr_0;
                            u1_reg <= u_curr_1;
                        end else begin
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