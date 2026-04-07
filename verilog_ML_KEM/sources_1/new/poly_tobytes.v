`timescale 1ns / 1ps
//=============================================================================
// Module: poly_tobytes
// FIPS 203 ByteEncode_12 — Serialize 256 coefficients (12-bit) → 384 bytes
//
// Packing scheme (little-endian, 2 coefficients → 3 bytes):
//   Byte 0: c0[7:0]
//   Byte 1: c1[3:0] | c0[11:8]
//   Byte 2: c1[11:4]
//
// Architecture:
//   - Reads coefficient pairs from dual-bank RAM (1 pair per address)
//   - Packs each pair into 3 bytes
//   - Writes bytes to output byte RAM
//   - Total: 128 pairs → 384 bytes
//
// Latency: ~128 × (3 read + 3 write) + overhead ≈ 640 cycles
//=============================================================================

module poly_tobytes (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start,
    output reg         done,

    // Input coefficient RAM (dual-bank read)
    output reg  [6:0]  coeff_addr,   // 0-127
    input  wire [15:0] coeff_a0,     // even coefficient (12-bit valid)
    input  wire [15:0] coeff_a1,     // odd coefficient (12-bit valid)

    // Output byte write interface
    output reg         byte_we,
    output reg  [8:0]  byte_addr,    // 0-383
    output reg  [7:0]  byte_dout
);

    //=========================================================================
    // FSM States
    //=========================================================================
    localparam S_IDLE    = 3'd0;
    localparam S_READ    = 3'd1;  // Issue read address
    localparam S_WAIT    = 3'd2;  // Wait for RAM data
    localparam S_PACK    = 3'd3;  // Compute 3 bytes from 2 coefficients
    localparam S_WRITE   = 3'd4;  // Write bytes sequentially
    localparam S_DONE    = 3'd5;

    reg [2:0] state;

    //=========================================================================
    // Internal Registers
    //=========================================================================
    reg [6:0]  pair_idx;    // current pair index (0-127)
    reg [8:0]  out_idx;     // output byte index
    reg [7:0]  packed [0:2]; // 3 packed bytes per pair
    reg [1:0]  wr_cnt;      // write counter (0-2)

    //=========================================================================
    // FSM
    //=========================================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state      <= S_IDLE;
            done       <= 1'b0;
            pair_idx   <= 7'd0;
            out_idx    <= 9'd0;
            coeff_addr <= 7'd0;
            byte_we    <= 1'b0;
            byte_addr  <= 9'd0;
            byte_dout  <= 8'd0;
            wr_cnt     <= 2'd0;
        end else begin
            byte_we <= 1'b0;

            case (state)
                S_IDLE: begin
                    done <= 1'b0;
                    if (start) begin
                        pair_idx   <= 7'd0;
                        out_idx    <= 9'd0;
                        coeff_addr <= 7'd0;
                        wr_cnt     <= 2'd0;
                        state      <= S_READ;
                    end
                end

                S_READ: begin
                    // coeff_addr already set
                    state <= S_WAIT;
                end

                S_WAIT: begin
                    state <= S_PACK;
                end

                S_PACK: begin
                    // Pack 2 × 12-bit → 3 × 8-bit
                    packed[0] <= coeff_a0[7:0];                           // c0[7:0]
                    packed[1] <= {coeff_a1[3:0], coeff_a0[11:8]};         // c1[3:0] | c0[11:8]
                    packed[2] <= coeff_a1[11:4];                          // c1[11:4]
                    wr_cnt    <= 2'd0;
                    state     <= S_WRITE;
                end

                S_WRITE: begin
                    byte_we   <= 1'b1;
                    byte_addr <= out_idx;
                    byte_dout <= packed[wr_cnt];
                    out_idx   <= out_idx + 9'd1;

                    if (wr_cnt == 2'd2) begin
                        // All 3 bytes written, move to next pair
                        pair_idx <= pair_idx + 7'd1;
                        if (pair_idx == 7'd127) begin
                            state <= S_DONE;
                        end else begin
                            coeff_addr <= pair_idx + 7'd1;
                            state      <= S_READ;
                        end
                    end else begin
                        wr_cnt <= wr_cnt + 2'd1;
                    end
                end

                S_DONE: begin
                    done  <= 1'b1;
                    state <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule
