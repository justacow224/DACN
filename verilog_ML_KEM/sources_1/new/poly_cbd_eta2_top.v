`timescale 1ns / 1ps

module poly_cbd_eta2_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    output reg          done,

    // SHAKE Output Buffer Interface (1-cycle read latency)
    output wire [3:0]   buf_addr,  // 0 to 15 (16 words of 64-bit)
    input  wire [63:0]  buf_dout,

    // RAM Interface (Write-Only to Bank A)
    output wire         ram_we,
    output wire [6:0]   ram_addr,  // 0 to 127
    output wire [15:0]  ram_a0_din,
    output wire [15:0]  ram_a1_din
);

    // =================================================================
    // 1. FSM STATES
    // =================================================================
    localparam IDLE      = 2'd0;
    localparam READ_WORD = 2'd1;
    localparam PROCESS   = 2'd2;

    reg [1:0]  state;
    reg [3:0]  word_idx; // 0 to 15
    reg [2:0]  byte_idx; // 0 to 7
    reg [55:0] word_reg; // Stores the remaining 7 bytes (56 bits)

    assign buf_addr = word_idx;

    // Dynamically pick the current byte: 
    // Directly from RAM on the first cycle, then from the shift register
    wire [7:0] current_byte = (state == PROCESS && byte_idx == 0) ? buf_dout[7:0] : word_reg[7:0];

    // =================================================================
    // 2. FSM & SHIFT REGISTER LOGIC
    // =================================================================
    always @(posedge clk) begin
        if (!rst_n) begin
            state    <= IDLE;
            word_idx <= 0;
            byte_idx <= 0;
            word_reg <= 0;
            done     <= 0;
        end else begin
            done <= 0;
            case (state)
                IDLE: begin
                    word_idx <= 0;
                    byte_idx <= 0;
                    if (start) state <= READ_WORD;
                end
                
                READ_WORD: begin
                    // buf_addr is driven to word_idx.
                    // RAM will output buf_dout at the next clock edge.
                    state <= PROCESS;
                end
                
                PROCESS: begin
                    // Shift the register to prepare the next byte
                    if (byte_idx == 0) begin
                        word_reg <= buf_dout[63:8];
                    end else begin
                        word_reg <= {8'd0, word_reg[55:8]};
                    end

                    // Cycle management
                    if (byte_idx == 7) begin
                        byte_idx <= 0;
                        if (word_idx == 15) begin
                            state <= IDLE;
                            done  <= 1;
                        end else begin
                            word_idx <= word_idx + 1;
                            state    <= READ_WORD;
                        end
                    end else begin
                        byte_idx <= byte_idx + 1;
                    end
                end
                
                default: state <= IDLE;
            endcase
        end
    end

    // =================================================================
    // 3. CBD MATH CORE (Combinational)
    // =================================================================
    wire [1:0] d0 = current_byte[0] + current_byte[1];
    wire [1:0] d1 = current_byte[2] + current_byte[3];
    wire [1:0] d2 = current_byte[4] + current_byte[5];
    wire [1:0] d3 = current_byte[6] + current_byte[7];

    // Subtract and cast to signed 3-bit numbers
    wire signed [2:0] a0_sub = $signed({1'b0, d0}) - $signed({1'b0, d1});
    wire signed [2:0] a1_sub = $signed({1'b0, d2}) - $signed({1'b0, d3});

    // Convert to Modulo 3329 if negative (check the sign bit `[2]`)
    wire [15:0] a0_out = (a0_sub[2]) ? (16'd3329 + {{13{a0_sub[2]}}, a0_sub}) : {13'd0, a0_sub};
    wire [15:0] a1_out = (a1_sub[2]) ? (16'd3329 + {{13{a1_sub[2]}}, a1_sub}) : {13'd0, a1_sub};

    // =================================================================
    // 4. WRITE TO DESTINATION RAM
    // =================================================================
    assign ram_we     = (state == PROCESS);
    assign ram_addr   = {word_idx, byte_idx}; // 4 bits + 3 bits = 7 bits (0 to 127)
    assign ram_a0_din = a0_out;
    assign ram_a1_din = a1_out;

endmodule