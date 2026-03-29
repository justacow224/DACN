`timescale 1ns / 1ps

module poly_parse_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    output reg          done,

    // SHAKE128 Output Buffer Interface
    output reg  [6:0]   buf_addr,  
    input  wire [63:0]  buf_dout,

    // RAM Interface (Bank A0, A1)
    output reg          ram_we_a0,
    output reg          ram_we_a1,
    output reg  [6:0]   ram_addr,  
    output reg  [15:0]  ram_a0_din,
    output reg  [15:0]  ram_a1_din
);

    // =================================================================
    // 1. FSM & REGISTERS
    // =================================================================
    localparam IDLE      = 2'd0;
    localparam FETCH_1   = 2'd1; 
    localparam FETCH_2   = 2'd2; 
    localparam PROCESS   = 2'd3;

    reg [1:0]  state;
    reg [8:0]  coeff_count; 
    
    reg [87:0] shift_reg;
    reg [6:0]  bit_count;   

    // =================================================================
    // 2. COMBINATIONAL LOGIC: PARSE & REJECT
    // =================================================================
    wire [23:0] current_24b = shift_reg[23:0];
    
    wire [7:0] b0 = current_24b[7:0];
    wire [7:0] b1 = current_24b[15:8];
    wire [7:0] b2 = current_24b[23:16];

    wire [11:0] d1 = {b1[3:0], b0};
    wire [11:0] d2 = {b2, b1[7:4]};

    localparam KYBER_Q = 12'd3329;
    wire valid_d1 = (d1 < KYBER_Q);
    wire valid_d2 = (d2 < KYBER_Q);

    wire space_for_2 = (coeff_count <= 254);
    wire space_for_1 = (coeff_count <= 255);

    // =================================================================
    // 3. MAIN STATE MACHINE
    // =================================================================
    always @(posedge clk) begin
        if (!rst_n) begin
            state       <= IDLE;
            buf_addr    <= 0;
            coeff_count <= 0;
            shift_reg   <= 0;
            bit_count   <= 0;
            
            ram_we_a0   <= 0;
            ram_we_a1   <= 0;
            ram_addr    <= 0;
            ram_a0_din  <= 0;
            ram_a1_din  <= 0;
            done        <= 0;
        end else begin
            ram_we_a0 <= 0;
            ram_we_a1 <= 0;
            done      <= 0;

            case (state)
                IDLE: begin
                    if (start) begin
                        buf_addr    <= 0;
                        coeff_count <= 0;
                        bit_count   <= 0;
                        shift_reg   <= 0;
                        ram_addr    <= 0; 
                        state       <= FETCH_1;
                    end
                end

                FETCH_1: begin
                    buf_addr <= buf_addr + 1;
                    state    <= FETCH_2;
                end

                FETCH_2: begin
                    shift_reg <= shift_reg | ({24'd0, buf_dout} << bit_count);
                    bit_count <= bit_count + 7'd64;
                    state     <= PROCESS;
                end

                PROCESS: begin
                    // SỬ DỤNG >= THAY VÌ == ĐỂ ĐẢM BẢO AN TOÀN TUYỆT ĐỐI
                    if (coeff_count >= 256) begin
                        state <= IDLE;
                        done  <= 1;
                    end
                    else if (bit_count < 24) begin
                        buf_addr <= buf_addr + 1;
                        state    <= FETCH_2;
                    end 
                    else begin
                        // Dịch thanh ghi 24 bit
                        shift_reg <= shift_reg >> 24;
                        bit_count <= bit_count - 24;

                        // FIX: KHÔNG DÙNG BIẾN TRUNG GIAN NUM_VALID. GÁN TRỰC TIẾP!
                        if (valid_d1 && valid_d2 && space_for_2) begin
                            if (coeff_count[0] == 1'b0) begin 
                                // Ghi chẵn: Ghi cả 2
                                ram_we_a0   <= 1; ram_a0_din <= {4'd0, d1};
                                ram_we_a1   <= 1; ram_a1_din <= {4'd0, d2};
                                coeff_count <= coeff_count + 2;
                                ram_addr    <= ram_addr + 1;
                            end else begin 
                                // Ghi lẻ: Chỉ ghi d1, bỏ d2 (Đúng thuật toán Rejection)
                                ram_we_a1   <= 1; ram_a1_din <= {4'd0, d1};
                                coeff_count <= coeff_count + 1;
                                ram_addr    <= ram_addr + 1;
                            end
                        end 
                        else if (valid_d1 && space_for_1) begin
                            // Chỉ có d1 hợp lệ
                            if (coeff_count[0] == 1'b0) begin
                                ram_we_a0   <= 1; ram_a0_din <= {4'd0, d1};
                                coeff_count <= coeff_count + 1;
                            end else begin
                                ram_we_a1   <= 1; ram_a1_din <= {4'd0, d1};
                                coeff_count <= coeff_count + 1;
                                ram_addr    <= ram_addr + 1; 
                            end
                        end
                        else if (valid_d2 && space_for_1) begin
                            // Chỉ có d2 hợp lệ
                            if (coeff_count[0] == 1'b0) begin
                                ram_we_a0   <= 1; ram_a0_din <= {4'd0, d2};
                                coeff_count <= coeff_count + 1;
                            end else begin
                                ram_we_a1   <= 1; ram_a1_din <= {4'd0, d2};
                                coeff_count <= coeff_count + 1;
                                ram_addr    <= ram_addr + 1;
                            end
                        end
                        // Else: Cả 2 đều bị Reject -> Tự động bỏ qua không tăng biến đếm
                    end
                end
            endcase
        end
    end

endmodule