`timescale 1ns / 1ps
//=============================================================================
// Module: poly_decompress
// FIPS 203 Algorithm 4 — Decompress_d(y) = round(q / 2^d * y)
//
// Supports d=1 (message decoding), d=4 (v decompression), d=10 (u decompression)
//
// Math: Decompress_d(y) = floor((q * y + 2^(d-1)) / 2^d)
//                        = (3329 * y + (1 << (d-1))) >> d
//
// This is MUCH simpler than Compress — just multiply + shift, no division.
//
// Output sizes: d=1 → from 32 bytes, d=4 → from 128 bytes, d=10 → from 320 bytes
// All produce 256 coefficients.
//=============================================================================

module poly_decompress (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start,
    input  wire [1:0]  d_sel,    // 00=d1(msg), 01=d4(v), 10=d10(u)
    output reg         done,

    // Input byte read interface
    output reg  [8:0]  byte_addr,    // 0-319 (max for d=10)
    input  wire [7:0]  byte_din,

    // Output coefficient RAM write interface (dual-bank)
    output reg         coeff_we,
    output reg  [6:0]  coeff_addr,   // 0-127
    output reg  [15:0] coeff_a0,     // even-index coefficient
    output reg  [15:0] coeff_a1      // odd-index coefficient
);

    //=========================================================================
    // FSM States
    //=========================================================================
    localparam S_IDLE        = 4'd0;
    localparam S_READ        = 4'd1;
    localparam S_WAIT        = 4'd2;
    localparam S_UNPACK      = 4'd3;
    localparam S_DECOMPRESS  = 4'd4;
    localparam S_WRITE       = 4'd5;
    localparam S_DONE        = 4'd6;
    // d=10 needs to read 5 bytes before unpacking
    localparam S_READ_D10    = 4'd7;
    localparam S_WAIT_D10    = 4'd8;
    localparam S_COLLECT_D10 = 4'd9;

    reg [3:0] state;

    //=========================================================================
    // Internal Registers
    //=========================================================================
    reg [6:0]  pair_idx;        // output coefficient pair index (0-127)
    reg [8:0]  in_idx;          // input byte index
    reg [1:0]  d_sel_r;

    // Unpacked compressed values
    reg [11:0] unpk_a0, unpk_a1;   // max 12-bit for d=12, but we only use up to 10-bit

    // d=10: need 5 bytes to unpack 4 values
    reg [7:0]  d10_bytes [0:4];
    reg [2:0]  d10_byte_cnt;
    reg [9:0]  d10_vals [0:3];
    reg [1:0]  d10_val_idx;        // which pair of 4 to write (0 or 2)

    // d=1: read 1 byte → 8 coefficients (4 pairs)
    reg [7:0]  d1_byte;
    reg [2:0]  d1_bit_idx;         // which pair within the byte (0,2,4,6)

    // Decompressed values
    reg [15:0] decomp_a0, decomp_a1;

    //=========================================================================
    // Decompress_d Core (Combinational)
    // Decompress_d(y) = (3329 * y + half) >> d
    //   d=1:  half=1,   shift=1,  y ∈ {0,1}   → result ∈ {0, 1665}
    //   d=4:  half=8,   shift=4,  y ∈ [0,15]   → result ∈ [0, 3121]
    //   d=10: half=512, shift=10, y ∈ [0,1023] → result ∈ [0, 3326]
    //=========================================================================
    wire [21:0] prod_a0_w = unpk_a0 * 13'd3329;
    wire [21:0] prod_a1_w = unpk_a1 * 13'd3329;

    wire [21:0] round_a0, round_a1;
    wire [15:0] result_a0, result_a1;

    assign round_a0 = (d_sel_r == 2'b00) ? prod_a0_w + 22'd1  :
                      (d_sel_r == 2'b01) ? prod_a0_w + 22'd8  :
                                           prod_a0_w + 22'd512;

    assign round_a1 = (d_sel_r == 2'b00) ? prod_a1_w + 22'd1  :
                      (d_sel_r == 2'b01) ? prod_a1_w + 22'd8  :
                                           prod_a1_w + 22'd512;

    assign result_a0 = (d_sel_r == 2'b00) ? {15'd0, round_a0[1]}     :
                       (d_sel_r == 2'b01) ? {4'd0, round_a0[15:4]}   :
                                            {4'd0, round_a0[21:10]}  ;

    assign result_a1 = (d_sel_r == 2'b00) ? {15'd0, round_a1[1]}     :
                       (d_sel_r == 2'b01) ? {4'd0, round_a1[15:4]}   :
                                            {4'd0, round_a1[21:10]}  ;

    //=========================================================================
    // FSM
    //=========================================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state        <= S_IDLE;
            done         <= 1'b0;
            pair_idx     <= 7'd0;
            in_idx       <= 9'd0;
            byte_addr    <= 9'd0;
            coeff_we     <= 1'b0;
            coeff_addr   <= 7'd0;
            coeff_a0     <= 16'd0;
            coeff_a1     <= 16'd0;
            d_sel_r      <= 2'd0;
            unpk_a0      <= 12'd0;
            unpk_a1      <= 12'd0;
            d1_bit_idx   <= 3'd0;
            d10_byte_cnt <= 3'd0;
            d10_val_idx  <= 2'd0;
        end else begin
            coeff_we <= 1'b0;

            case (state)
                //-------------------------------------------------------------
                S_IDLE: begin
                    done <= 1'b0;
                    if (start) begin
                        pair_idx     <= 7'd0;
                        in_idx       <= 9'd0;
                        d_sel_r      <= d_sel;
                        d1_bit_idx   <= 3'd0;
                        d10_byte_cnt <= 3'd0;
                        d10_val_idx  <= 2'd0;
                        byte_addr    <= 9'd0;

                        // Choose initial read state based on d
                        case (d_sel)
                            2'b10:   state <= S_READ_D10;  // d=10: read 5 bytes
                            default: state <= S_READ;       // d=1, d=4: read 1 byte
                        endcase
                    end
                end

                //-------------------------------------------------------------
                // d=1 and d=4: Read 1 byte
                //-------------------------------------------------------------
                S_READ: begin
                    byte_addr <= in_idx;
                    state     <= S_WAIT;
                end

                S_WAIT: begin
                    state <= S_UNPACK;
                end

                //-------------------------------------------------------------
                // Unpack bytes → compressed values
                //-------------------------------------------------------------
                S_UNPACK: begin
                    case (d_sel_r)
                        // d=1: 1 byte → 8 bits → 8 coefficients (4 pairs)
                        2'b00: begin
                            d1_byte    <= byte_din;
                            unpk_a0    <= {11'd0, byte_din[d1_bit_idx]};
                            unpk_a1    <= {11'd0, byte_din[d1_bit_idx + 3'd1]};
                            state      <= S_DECOMPRESS;
                        end

                        // d=4: 1 byte → 2 nibbles → 2 coefficients (1 pair)
                        2'b01: begin
                            unpk_a0 <= {8'd0, byte_din[3:0]};
                            unpk_a1 <= {8'd0, byte_din[7:4]};
                            in_idx  <= in_idx + 9'd1;
                            state   <= S_DECOMPRESS;
                        end

                        default: state <= S_DONE;
                    endcase
                end

                //-------------------------------------------------------------
                // d=10: Read 5 bytes sequentially
                //-------------------------------------------------------------
                S_READ_D10: begin
                    byte_addr <= in_idx;
                    state     <= S_WAIT_D10;
                end

                S_WAIT_D10: begin
                    state <= S_COLLECT_D10;
                end

                S_COLLECT_D10: begin
                    d10_bytes[d10_byte_cnt] <= byte_din;
                    in_idx <= in_idx + 9'd1;

                    if (d10_byte_cnt == 3'd4) begin
                        // All 5 bytes collected, unpack 4 × 10-bit values
                        // Using combinational unpack from collected + current byte_din
                        // d10_bytes[0..3] are registered, d10_bytes[4] = byte_din (current)
                        d10_vals[0] <= {d10_bytes[1][1:0], d10_bytes[0]};
                        d10_vals[1] <= {d10_bytes[2][3:0], d10_bytes[1][7:2]};
                        d10_vals[2] <= {d10_bytes[3][5:0], d10_bytes[2][7:4]};
                        d10_vals[3] <= {byte_din[7:0],     d10_bytes[3][7:6]};

                        d10_byte_cnt <= 3'd0;
                        d10_val_idx  <= 2'd0;

                        // Set up first pair for decompression
                        unpk_a0 <= {2'd0, d10_bytes[1][1:0], d10_bytes[0]};
                        unpk_a1 <= {2'd0, d10_bytes[2][3:0], d10_bytes[1][7:2]};
                        state   <= S_DECOMPRESS;
                    end else begin
                        d10_byte_cnt <= d10_byte_cnt + 3'd1;
                        state        <= S_READ_D10;
                    end
                end

                //-------------------------------------------------------------
                // Decompress: compute result from unpacked values
                //-------------------------------------------------------------
                S_DECOMPRESS: begin
                    decomp_a0 <= result_a0;
                    decomp_a1 <= result_a1;
                    state     <= S_WRITE;
                end

                //-------------------------------------------------------------
                // Write results to coefficient RAM
                //-------------------------------------------------------------
                S_WRITE: begin
                    coeff_we   <= 1'b1;
                    coeff_addr <= pair_idx;
                    coeff_a0   <= decomp_a0;
                    coeff_a1   <= decomp_a1;

                    pair_idx <= pair_idx + 7'd1;

                    if (pair_idx == 7'd127) begin
                        state <= S_DONE;
                    end else begin
                        case (d_sel_r)
                            // d=1: 4 pairs per byte
                            2'b00: begin
                                if (d1_bit_idx == 3'd6) begin
                                    // Byte exhausted, read next
                                    d1_bit_idx <= 3'd0;
                                    in_idx     <= in_idx + 9'd1;
                                    state      <= S_READ;
                                end else begin
                                    // Next pair from same byte
                                    d1_bit_idx <= d1_bit_idx + 3'd2;
                                    unpk_a0    <= {11'd0, d1_byte[d1_bit_idx + 3'd2]};
                                    unpk_a1    <= {11'd0, d1_byte[d1_bit_idx + 3'd3]};
                                    state      <= S_DECOMPRESS;
                                end
                            end

                            // d=4: 1 pair per byte
                            2'b01: begin
                                state <= S_READ;
                            end

                            // d=10: 2 pairs per 5-byte group
                            2'b10: begin
                                if (d10_val_idx == 2'd0) begin
                                    // Second pair from same group
                                    d10_val_idx <= 2'd2;
                                    unpk_a0     <= d10_vals[2];
                                    unpk_a1     <= d10_vals[3];
                                    state       <= S_DECOMPRESS;
                                end else begin
                                    // Group exhausted, read next 5 bytes
                                    d10_val_idx <= 2'd0;
                                    state       <= S_READ_D10;
                                end
                            end

                            default: state <= S_DONE;
                        endcase
                    end
                end

                //-------------------------------------------------------------
                S_DONE: begin
                    done  <= 1'b1;
                    state <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule
