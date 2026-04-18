`timescale 1ns / 1ps
//=============================================================================
// Module: poly_frommsg
// FIPS 203 Decompress_1 for message encoding:
//   coeff[k] = ((msg[byte] >> bit) & 1) ? ceil(q/2) : 0
// with q=3329, ceil(q/2)=1665.
//
// Input: 32 bytes message
// Output: 256 coefficients as 128 pairs (a0/a1)
//=============================================================================

module poly_frommsg (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start,
    output reg         done,

    // Message byte input (1-cycle read latency)
    output reg  [4:0]  msg_addr,
    input  wire [7:0]  msg_din,

    // Coefficient pair output
    output reg         coeff_we,
    output reg  [6:0]  coeff_addr,
    output reg  [15:0] coeff_a0,
    output reg  [15:0] coeff_a1
);

    localparam [2:0] S_IDLE      = 3'd0;
    localparam [2:0] S_READ      = 3'd1;
    localparam [2:0] S_WAIT      = 3'd2;
    localparam [2:0] S_WRITEPAIR = 3'd3;
    localparam [2:0] S_DONE      = 3'd4;

    localparam [15:0] MSG_ONE_COEFF = 16'd1665;

    reg [2:0] state;

    reg [4:0] byte_idx;
    reg [1:0] pair_in_byte;
    reg [7:0] msg_byte_reg;

    wire bit0 = msg_byte_reg[{pair_in_byte, 1'b0}];
    wire bit1 = msg_byte_reg[{pair_in_byte, 1'b0} + 1'b1];

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state        <= S_IDLE;
            done         <= 1'b0;
            coeff_we     <= 1'b0;
            msg_addr     <= 5'd0;
            coeff_addr   <= 7'd0;
            coeff_a0     <= 16'd0;
            coeff_a1     <= 16'd0;
            byte_idx     <= 5'd0;
            pair_in_byte <= 2'd0;
            msg_byte_reg <= 8'd0;
        end else begin
            coeff_we <= 1'b0;

            case (state)
                S_IDLE: begin
                    done <= 1'b0;
                    if (start) begin
                        byte_idx     <= 5'd0;
                        pair_in_byte <= 2'd0;
                        msg_addr     <= 5'd0;
                        coeff_addr   <= 7'd0;
                        state        <= S_READ;
                    end
                end

                S_READ: begin
                    msg_addr <= byte_idx;
                    state    <= S_WAIT;
                end

                S_WAIT: begin
                    msg_byte_reg <= msg_din;
                    pair_in_byte <= 2'd0;
                    state        <= S_WRITEPAIR;
                end

                S_WRITEPAIR: begin
                    coeff_we   <= 1'b1;
                    coeff_addr <= {byte_idx, 2'b00} + {5'd0, pair_in_byte};
                    coeff_a0   <= bit0 ? MSG_ONE_COEFF : 16'd0;
                    coeff_a1   <= bit1 ? MSG_ONE_COEFF : 16'd0;

                    if (pair_in_byte == 2'd3) begin
                        if (byte_idx == 5'd31) begin
                            state <= S_DONE;
                        end else begin
                            byte_idx <= byte_idx + 5'd1;
                            state    <= S_READ;
                        end
                    end else begin
                        pair_in_byte <= pair_in_byte + 2'd1;
                        state        <= S_WRITEPAIR;
                    end
                end

                S_DONE: begin
                    done  <= 1'b1;
                    state <= S_IDLE;
                end

                default: begin
                    state <= S_IDLE;
                end
            endcase
        end
    end

endmodule
