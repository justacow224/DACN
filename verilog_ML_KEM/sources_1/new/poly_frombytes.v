`timescale 1ns / 1ps
//=============================================================================
// Module: poly_frombytes
// FIPS 203 ByteDecode_12 — Deserialize 384 bytes → 256 coefficients (12-bit)
//
// Unpacking scheme (little-endian, 3 bytes → 2 coefficients):
//   c0 = byte[0] | (byte[1] & 0x0F) << 8
//   c1 = (byte[1] >> 4) | byte[2] << 4
//
// Architecture:
//   - Reads 3 bytes from input byte RAM per iteration
//   - Unpacks into 2 coefficients
//   - Writes both to output dual-bank RAM
//   - Total: 128 iterations → 384 bytes → 256 coefficients
//
// Latency: ~128 × (3 read + 1 write) + overhead ≈ 640 cycles
//=============================================================================

module poly_frombytes (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start,
    output reg         done,

    // Input byte read interface
    output reg  [8:0]  byte_addr,    // 0-383
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
    localparam S_IDLE    = 3'd0;
    localparam S_RD_B0   = 3'd1;  // Read byte 0
    localparam S_RD_B1   = 3'd2;  // Read byte 1
    localparam S_RD_B2   = 3'd3;  // Read byte 2
    localparam S_WAIT    = 3'd4;  // Wait for last byte
    localparam S_UNPACK  = 3'd5;  // Unpack 3 bytes → 2 coefficients
    localparam S_WRITE   = 3'd6;  // Write coefficient pair
    localparam S_DONE    = 3'd7;

    reg [2:0] state;

    //=========================================================================
    // Internal Registers
    //=========================================================================
    reg [6:0]  pair_idx;     // output pair index (0-127)
    reg [8:0]  in_idx;       // input byte index
    reg [7:0]  b0, b1, b2;  // 3 collected bytes
    reg [1:0]  rd_phase;     // which byte we're reading (0/1/2)

    //=========================================================================
    // FSM
    //=========================================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state      <= S_IDLE;
            done       <= 1'b0;
            pair_idx   <= 7'd0;
            in_idx     <= 9'd0;
            byte_addr  <= 9'd0;
            coeff_we   <= 1'b0;
            coeff_addr <= 7'd0;
            coeff_a0   <= 16'd0;
            coeff_a1   <= 16'd0;
            rd_phase   <= 2'd0;
            b0         <= 8'd0;
            b1         <= 8'd0;
            b2         <= 8'd0;
        end else begin
            coeff_we <= 1'b0;

            case (state)
                S_IDLE: begin
                    done <= 1'b0;
                    if (start) begin
                        pair_idx <= 7'd0;
                        in_idx   <= 9'd0;
                        rd_phase <= 2'd0;

                        // Start reading first byte
                        byte_addr <= 9'd0;
                        state     <= S_RD_B0;
                    end
                end

                // Read 3 bytes with proper pipelining
                // Each byte read: set addr → wait 1 cycle → capture data
                S_RD_B0: begin
                    // Address was set before entering this state
                    // Wait one cycle for BRAM latency
                    byte_addr <= in_idx + 9'd1;  // Pre-set next address
                    state     <= S_RD_B1;
                end

                S_RD_B1: begin
                    b0        <= byte_din;       // Capture byte 0
                    byte_addr <= in_idx + 9'd2;  // Pre-set byte 2 address
                    state     <= S_RD_B2;
                end

                S_RD_B2: begin
                    b1    <= byte_din;            // Capture byte 1
                    state <= S_WAIT;
                end

                S_WAIT: begin
                    b2     <= byte_din;           // Capture byte 2
                    in_idx <= in_idx + 9'd3;      // Advance input index by 3
                    state  <= S_UNPACK;
                end

                S_UNPACK: begin
                    // Unpack 3 bytes → 2 coefficients
                    coeff_a0 <= {4'd0, b1[3:0], b0[7:0]};     // c0 = b0 | (b1 & 0x0F) << 8
                    coeff_a1 <= {4'd0, b2[7:0], b1[7:4]};     // c1 = (b1 >> 4) | b2 << 4
                    state    <= S_WRITE;
                end

                S_WRITE: begin
                    coeff_we   <= 1'b1;
                    coeff_addr <= pair_idx;
                    // coeff_a0, coeff_a1 already set

                    pair_idx <= pair_idx + 7'd1;
                    if (pair_idx == 7'd127) begin
                        state <= S_DONE;
                    end else begin
                        // Set up next read
                        byte_addr <= in_idx;
                        state     <= S_RD_B0;
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
