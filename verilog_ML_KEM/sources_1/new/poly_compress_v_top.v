`timescale 1ns / 1ps

module poly_compress_v_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    output reg          done,

    output reg  [6:0]   ram_addr,  
    input  wire [15:0]  ram_a0_dout,
    input  wire [15:0]  ram_a1_dout,

    // Output Buffer Interface (Write 64-bit words)
    // 128 bytes = 16 words of 64-bit
    output reg          buf_we,
    output reg  [5:0]   buf_addr,   // 0 to 15
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

    // Đệm chứa tối đa 64 bit (8 bytes)
    reg [63:0]  shift_reg;     
    reg [3:0]   byte_count; // Đếm số byte đã gom (0 to 8)
    reg [5:0]   out_word_count;

    // =================================================================
    // 2. MATH CORE: NORMALIZE & MAGIC MULTIPLIER (d=4)
    // =================================================================
    wire signed [15:0] in0 = ram_a0_dout;
    wire signed [15:0] in1 = ram_a1_dout;

    // Normalize
    wire [15:0] norm0 = (in0 < 0) ? (in0 + 16'd3329) : (in0 >= 16'd3329) ? (in0 - 16'd3329) : in0;
    wire [15:0] norm1 = (in1 < 0) ? (in1 + 16'd3329) : (in1 >= 16'd3329) ? (in1 - 16'd3329) : in1;

    // T = val * 16 + 1664 (Vì d=4)
    wire [31:0] t0 = ({16'd0, norm0} << 4) + 32'd1664;
    wire [31:0] t1 = ({16'd0, norm1} << 4) + 32'd1664;

    // Magic Division: / 3329
    wire [63:0] prod0 = t0 * 64'd2580335;
    wire [63:0] prod1 = t1 * 64'd2580335;

    // U = 4 bit
    wire [3:0] u_curr_0 = (prod0 >> 33) & 4'hF;
    wire [3:0] u_curr_1 = (prod1 >> 33) & 4'hF;

    // =================================================================
    // 3. PACKING LOGIC (Trực tiếp và đơn giản)
    // =================================================================
    // Ghép thẳng 2 hệ số thành 1 byte: u1 nằm cao, u0 nằm thấp
    wire [7:0] new_byte = {u_curr_1, u_curr_0};
    
    // Nhồi byte mới vào thanh ghi dịch
    wire [63:0] merged_shift = shift_reg | ({56'd0, new_byte} << (byte_count * 8));
    
    // Nếu gom đủ 8 bytes (1 word 64-bit) -> Xả!
    wire write_trigger = (byte_count == 4'd7);

    // =================================================================
    // 4. MAIN PIPELINE
    // =================================================================
    always @(posedge clk) begin
        if (!rst_n) begin
            state          <= IDLE;
            req_count      <= 0;
            process_count  <= 0;
            val_pipe       <= 2'b00;
            shift_reg      <= 0;
            byte_count     <= 0;
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
                        byte_count     <= 0;
                        buf_addr       <= 0;
                        out_word_count <= 0;
                        state          <= PIPE;
                    end
                end

                PIPE: begin
                    // --- STAGE 1 ---
                    if (req_count < 128) begin
                        ram_addr  <= req_count[6:0];
                        req_count <= req_count + 1;
                        val_pipe  <= {val_pipe[0], 1'b1};
                    end else begin
                        val_pipe  <= {val_pipe[0], 1'b0};
                    end

                    // --- STAGE 2 & 3 ---
                    if (val_pipe[1]) begin
                        if (write_trigger) begin
                            buf_we   <= 1;
                            buf_din  <= merged_shift[63:0];
                            
                            buf_addr       <= out_word_count;
                            out_word_count <= out_word_count + 1;
                            
                            // Reset bộ đệm sau khi xả
                            shift_reg  <= 0;
                            byte_count <= 0;
                        end else begin
                            shift_reg  <= merged_shift;
                            byte_count <= byte_count + 1;
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