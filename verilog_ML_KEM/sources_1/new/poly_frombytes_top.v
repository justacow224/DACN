`timescale 1ns / 1ps

module poly_frombytes_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    output reg          done,

    output reg  [5:0]   buf_addr,  
    input  wire [63:0]  buf_dout,

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
    reg [7:0]  iter_count;  
    
    reg [87:0] shift_reg;
    reg [6:0]  bit_count;

    // =================================================================
    // 2. COMBINATIONAL LOGIC: BYTES TO POLY
    // =================================================================
    wire [23:0] current_24b = shift_reg[23:0];
    
    wire [7:0] a = current_24b[7:0];
    wire [7:0] b = current_24b[15:8];
    wire [7:0] c = current_24b[23:16];

    wire [11:0] c0 = {b[3:0], a};
    wire [11:0] c1 = {c, b[7:4]};

    // =================================================================
    // 3. MAIN STATE MACHINE
    // =================================================================
    always @(posedge clk) begin
        if (!rst_n) begin
            state      <= IDLE;
            buf_addr   <= 0;
            iter_count <= 0;
            shift_reg  <= 0;
            bit_count  <= 0;
            ram_we_a0  <= 0;
            ram_we_a1  <= 0;
            ram_addr   <= 0;
            ram_a0_din <= 0;
            ram_a1_din <= 0;
            done       <= 0;
        end else begin
            ram_we_a0 <= 0;
            ram_we_a1 <= 0;
            done      <= 0;

            case (state)
                IDLE: begin
                    if (start) begin
                        buf_addr   <= 0;
                        iter_count <= 0;
                        bit_count  <= 0;
                        shift_reg  <= 0;
                        ram_addr   <= 0;
                        state      <= FETCH_1;
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
                    if (iter_count == 128) begin
                        state <= IDLE;
                        done  <= 1;
                    end
                    else if (bit_count < 24) begin
                        buf_addr <= buf_addr + 1;
                        state    <= FETCH_2;
                    end 
                    else begin
                        ram_we_a0  <= 1;
                        ram_a0_din <= {4'd0, c0};
                        
                        ram_we_a1  <= 1;
                        ram_a1_din <= {4'd0, c1};

                        shift_reg  <= shift_reg >> 24;
                        bit_count  <= bit_count - 24;

                        // FIX: Đồng bộ địa chỉ ghi RAM bằng chính iter_count
                        ram_addr   <= iter_count;
                        iter_count <= iter_count + 1;
                    end
                end
            endcase
        end
    end

endmodule