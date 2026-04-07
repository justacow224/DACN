`timescale 1ns / 1ps
//=============================================================================
// Module: poly_compress
// FIPS 203 Algorithm 3 — Compress_d(x) = floor((x * 2^d + (q-1)/2) / q) mod 2^d
//
// Supports d=1 (message encoding), d=4 (v compression), d=10 (u compression)
//
// Architecture:
//   - Sequentially reads coefficient pairs from input RAM
//   - Compresses each coefficient using Barrett-style division by q=3329
//   - Packs compressed values into bytes and writes to output RAM
//
// Division by 3329 (exact Barrett):
//   quotient = floor(t * 161271 >> 29)
//   where t = x * 2^d + 1664
//   V = 161271, N = 29: proven zero-error by exhaustive verification.
//

// Output sizes: d=1 → 32 bytes, d=4 → 128 bytes, d=10 → 320 bytes
//=============================================================================

module poly_compress (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start,
    input  wire [1:0]  d_sel,    // 00=d1(msg), 01=d4(v), 10=d10(u)
    output reg         done,

    // Input coefficient RAM read interface (dual-bank)
    output reg  [6:0]  coeff_addr,   // 0-127, reads 2 coefficients per address
    input  wire [15:0] coeff_a0,     // even-index coefficient
    input  wire [15:0] coeff_a1,     // odd-index coefficient

    // Output byte write interface
    output reg         byte_we,
    output reg  [8:0]  byte_addr,    // 0-319 (max for d=10)
    output reg  [7:0]  byte_dout
);

    //=========================================================================
    // FSM States
    //=========================================================================
    localparam S_IDLE     = 4'd0;
    localparam S_READ     = 4'd1;  // Issue RAM read address
    localparam S_WAIT     = 4'd2;  // Wait for RAM data (1-cycle latency)
    localparam S_COMPRESS = 4'd3;  // Compute Compress_d for a0, a1
    localparam S_PACK_D1  = 4'd4;  // d=1: accumulate bits into byte
    localparam S_PACK_D4  = 4'd5;  // d=4: pack 2 nibbles → 1 byte
    localparam S_PACK_D10 = 4'd6;  // d=10: accumulate 4 values, write 5 bytes
    localparam S_WRITE_D10= 4'd7;  // d=10: sequentially write 5 packed bytes
    localparam S_DONE     = 4'd8;

    reg [3:0] state;

    //=========================================================================
    // Internal Registers
    //=========================================================================
    reg [6:0]  idx;             // coefficient pair index (0-127)
    reg [8:0]  out_idx;         // output byte write index
    reg [1:0]  d_sel_r;         // registered d_sel

    // Compressed values
    reg [9:0]  comp_val0, comp_val1;

    // d=1 message accumulation
    reg [7:0]  msg_acc;         // accumulate 8 bits
    reg [2:0]  bit_pos;         // current bit position (0,2,4,6)

    // d=10 accumulation buffer: collect 4 × 10-bit, then pack 5 bytes
    reg [9:0]  u10_buf [0:3];
    reg [1:0]  u10_cnt;         // how many values stored (0-3), fill by 2s
    reg [2:0]  wr10_cnt;        // write counter for 5 bytes (0-4)

    // Packed bytes for d=10 (precomputed from 4 × 10-bit values)
    reg [7:0]  packed_bytes [0:4];

    //=========================================================================
    // Compress_d Core Computation (Combinational)
    //
    // Compress_d(x) = floor((x * 2^d + 1664) / 3329) & ((1<<d)-1)
    //
    // Barrett division (exact for all valid inputs):
    //   quotient = floor(t * 161271 >> 29)
    //   where t = x * 2^d + 1664
    //
    // V = 161271, N = 29: proven zero-error by exhaustive verification
    // over all x ∈ [0, 3328] for d ∈ {1, 4, 10}.
    // Max product: 3409536 * 161271 = ~5.5e11 → needs 40 bits.
    // Fits in 1 DSP48E2 (27×18 + accumulate mode).
    //=========================================================================

    wire [21:0] scaled_a0, scaled_a1;
    wire [21:0] t_a0, t_a1;
    wire [50:0] prod_a0, prod_a1;   // 22 × 18 = up to 40-bit result
    wire [21:0] quot_a0, quot_a1;

    // Scale: x * 2^d
    assign scaled_a0 = (d_sel_r == 2'b00) ? {10'b0, coeff_a0[11:0]} << 1  :
                       (d_sel_r == 2'b01) ? {6'b0,  coeff_a0[11:0]} << 4  :
                                            {10'b0, coeff_a0[11:0]} << 10 ;

    assign scaled_a1 = (d_sel_r == 2'b00) ? {10'b0, coeff_a1[11:0]} << 1  :
                       (d_sel_r == 2'b01) ? {6'b0,  coeff_a1[11:0]} << 4  :
                                            {10'b0, coeff_a1[11:0]} << 10 ;

    // Add rounding term: (q-1)/2 = 1664
    assign t_a0 = scaled_a0 + 22'd1664;
    assign t_a1 = scaled_a1 + 22'd1664;

    // Barrett division: quotient = floor(t * 161271 >> 29)
    // V = 161271 (18-bit), N = 29
    assign prod_a0 = t_a0 * 18'd161271;
    assign prod_a1 = t_a1 * 18'd161271;

    assign quot_a0 = prod_a0[50:29];
    assign quot_a1 = prod_a1[50:29];

    //=========================================================================
    // FSM
    //=========================================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state      <= S_IDLE;
            done       <= 1'b0;
            idx        <= 7'd0;
            out_idx    <= 9'd0;
            byte_we    <= 1'b0;
            byte_addr  <= 9'd0;
            byte_dout  <= 8'd0;
            coeff_addr <= 7'd0;
            comp_val0  <= 10'd0;
            comp_val1  <= 10'd0;
            d_sel_r    <= 2'd0;
            msg_acc    <= 8'd0;
            bit_pos    <= 3'd0;
            u10_cnt    <= 2'd0;
            wr10_cnt   <= 3'd0;
        end else begin
            // Default: deassert write enable
            byte_we <= 1'b0;

            case (state)
                //-------------------------------------------------------------
                S_IDLE: begin
                    done <= 1'b0;
                    if (start) begin
                        idx        <= 7'd0;
                        out_idx    <= 9'd0;
                        d_sel_r    <= d_sel;
                        msg_acc    <= 8'd0;
                        bit_pos    <= 3'd0;
                        u10_cnt    <= 2'd0;
                        wr10_cnt   <= 3'd0;
                        coeff_addr <= 7'd0;
                        state      <= S_READ;
                    end
                end

                //-------------------------------------------------------------
                S_READ: begin
                    // Address already driven, wait for BRAM read latency
                    state <= S_WAIT;
                end

                //-------------------------------------------------------------
                S_WAIT: begin
                    // Data available on coeff_a0, coeff_a1 next cycle
                    state <= S_COMPRESS;
                end

                //-------------------------------------------------------------
                S_COMPRESS: begin
                    // Register compressed values with masking
                    case (d_sel_r)
                        2'b00: begin // d=1
                            comp_val0 <= {9'd0, quot_a0[0]};
                            comp_val1 <= {9'd0, quot_a1[0]};
                            state     <= S_PACK_D1;
                        end
                        2'b01: begin // d=4
                            comp_val0 <= {6'd0, quot_a0[3:0]};
                            comp_val1 <= {6'd0, quot_a1[3:0]};
                            state     <= S_PACK_D4;
                        end
                        2'b10: begin // d=10
                            comp_val0 <= quot_a0[9:0];
                            comp_val1 <= quot_a1[9:0];
                            state     <= S_PACK_D10;
                        end
                        default: state <= S_DONE;
                    endcase
                end

                //-------------------------------------------------------------
                // d=1: Accumulate 2 bits per pair, emit byte every 4 pairs
                //-------------------------------------------------------------
                S_PACK_D1: begin
                    msg_acc[bit_pos]       <= comp_val0[0];
                    msg_acc[bit_pos + 3'd1] <= comp_val1[0];

                    if (bit_pos == 3'd6) begin
                        // Byte complete: write out
                        byte_we   <= 1'b1;
                        byte_addr <= out_idx;
                        // Construct full byte (bits 0-5 already in msg_acc, 6-7 are current)
                        byte_dout <= {comp_val1[0], comp_val0[0], msg_acc[5:0]};
                        out_idx   <= out_idx + 9'd1;
                        msg_acc   <= 8'd0;
                        bit_pos   <= 3'd0;
                    end else begin
                        bit_pos <= bit_pos + 3'd2;
                    end

                    // Next pair
                    idx <= idx + 7'd1;
                    if (idx == 7'd127)
                        state <= S_DONE;
                    else begin
                        coeff_addr <= idx + 7'd1;
                        state      <= S_READ;
                    end
                end

                //-------------------------------------------------------------
                // d=4: 2 nibbles → 1 byte, write immediately
                //-------------------------------------------------------------
                S_PACK_D4: begin
                    byte_we   <= 1'b1;
                    byte_addr <= out_idx;
                    byte_dout <= {comp_val1[3:0], comp_val0[3:0]};
                    out_idx   <= out_idx + 9'd1;

                    // Next pair
                    idx <= idx + 7'd1;
                    if (idx == 7'd127)
                        state <= S_DONE;
                    else begin
                        coeff_addr <= idx + 7'd1;
                        state      <= S_READ;
                    end
                end

                //-------------------------------------------------------------
                // d=10: Accumulate 4 values (2 pairs), then pack 5 bytes
                // Packing scheme (from HLS / FIPS 203):
                //   u[0..3] = 4 compressed 10-bit values
                //   Byte 0: u0[7:0]
                //   Byte 1: {u1[5:0], u0[9:8]}
                //   Byte 2: {u2[3:0], u1[9:6]}
                //   Byte 3: {u3[1:0], u2[9:4]}
                //   Byte 4: u3[9:2]
                //-------------------------------------------------------------
                S_PACK_D10: begin
                    u10_buf[u10_cnt]       <= comp_val0;
                    u10_buf[u10_cnt + 2'd1] <= comp_val1;

                    if (u10_cnt == 2'd2) begin
                        // All 4 values available:
                        //   u10_buf[0] = u[0] (from previous pair, registered)
                        //   u10_buf[1] = u[1] (from previous pair, registered)
                        //   comp_val0  = u[2] (current pair)
                        //   comp_val1  = u[3] (current pair)
                        packed_bytes[0] <= u10_buf[0][7:0];
                        packed_bytes[1] <= {u10_buf[1][5:0], u10_buf[0][9:8]};
                        packed_bytes[2] <= {comp_val0[3:0], u10_buf[1][9:6]};
                        packed_bytes[3] <= {comp_val1[1:0], comp_val0[9:4]};
                        packed_bytes[4] <= comp_val1[9:2];

                        wr10_cnt   <= 3'd0;
                        u10_cnt    <= 2'd0;
                        state      <= S_WRITE_D10;
                    end else begin
                        u10_cnt <= u10_cnt + 2'd2;
                        // Read next pair
                        idx        <= idx + 7'd1;
                        coeff_addr <= idx + 7'd1;
                        state      <= S_READ;
                    end
                end

                //-------------------------------------------------------------
                // d=10: Write 5 packed bytes sequentially
                //-------------------------------------------------------------
                S_WRITE_D10: begin
                    byte_we   <= 1'b1;
                    byte_addr <= out_idx;
                    byte_dout <= packed_bytes[wr10_cnt];
                    out_idx   <= out_idx + 9'd1;

                    if (wr10_cnt == 3'd4) begin
                        // All 5 bytes written
                        idx <= idx + 7'd1;
                        if (idx == 7'd127)
                            state <= S_DONE;
                        else begin
                            coeff_addr <= idx + 7'd1;
                            state      <= S_READ;
                        end
                    end else begin
                        wr10_cnt <= wr10_cnt + 3'd1;
                        // Stay in WRITE_D10
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
