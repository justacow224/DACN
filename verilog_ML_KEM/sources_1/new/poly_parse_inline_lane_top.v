`timescale 1ns / 1ps

// R-new-B Phase G2: lane-mode SHAKE-128 parse-and-reject for matrix-A.
//
// Input: 64-bit lane stream from sponge (squeeze_lane_mode = 1).
// Output: up to 2 valid coefs/cycle to dual-port a_hat_mem.
//
// Throughput target: 3 bytes/cycle (1 cyc per 3-byte chunk producing up to 2
// candidates), vs ~1.5 byte/cycle in the legacy byte-FSM parse. ~2x faster
// for the matrix-A XOF.
//
// Design notes:
//   * 128-bit byte_buf accumulator. Refill from sponge whenever byte_count
//     ≤ 8 AND we still need more coefs.
//   * Every cycle in RUN, if buf has ≥ 3 bytes, consume 3 bytes (regardless
//     of rejection outcome — the legacy module also consumed 3 bytes per
//     PARSE_WRITE).
//   * Refill and consume can happen in the same cycle. Combinational next-
//     state logic handles the ordering: refill places the new lane at slot
//     byte_count (above existing data), then consume shifts the whole buf
//     down by 24 bits and decrements count by 3.
//   * FLUSH_D2 sub-state preserves the legacy odd-alignment write
//     sequencing — d2 deferred to next pair when current coeff_count was
//     odd entering RUN.

module poly_parse_inline_lane_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    output reg          done,

    // Lane-mode SHAKE-128 input
    input  wire [63:0]  lane_din,
    input  wire         lane_din_valid,
    output wire         lane_din_ready,

    // RAM write interface (pair-per-address, dual port a0/a1)
    output reg          ram_we_a0,
    output reg          ram_we_a1,
    output reg  [6:0]   ram_addr,
    output reg  [15:0]  ram_a0_din,
    output reg  [15:0]  ram_a1_din
);

    localparam IDLE     = 2'd0;
    localparam RUN      = 2'd1;
    localparam FLUSH_D2 = 2'd2;

    localparam [11:0] KYBER_Q = 12'd3329;

    reg [1:0]   state;
    reg [127:0] byte_buf;
    reg [4:0]   byte_count;   // 0..16 valid bytes
    reg [8:0]   coeff_count;  // 0..256
    reg [6:0]   ram_ptr;
    reg [11:0]  pending_d2;
    reg         pending_d2_valid;

    // Lane handshake: pull a fresh 8-byte lane whenever buf has room and
    // we still need more coefs. RUN-only (don't fetch in IDLE/FLUSH_D2).
    assign lane_din_ready = (state == RUN) &&
                            (byte_count <= 5'd8) &&
                            (coeff_count < 9'd256);

    wire refilling = lane_din_valid && lane_din_ready;

    // Compute post-refill view of buffer (refill places new lane at slot
    // byte_count, leaving low bytes intact). Variable shift is small here
    // because byte_count ≤ 8 when refilling (lane_din_ready gate).
    wire [127:0] lane_extended    = {64'd0, lane_din};
    wire [127:0] buf_after_refill = refilling
                                    ? (byte_buf | (lane_extended << (byte_count * 8)))
                                    : byte_buf;
    wire [4:0]   cnt_after_refill = byte_count + (refilling ? 5'd8 : 5'd0);

    // Two 12-bit candidates from the post-refill low 3 bytes — must use
    // post-refill view because the refill happens this cycle and parse
    // must see the new bytes if buf was empty/short.
    wire [7:0]  b0 = buf_after_refill[7:0];
    wire [7:0]  b1 = buf_after_refill[15:8];
    wire [7:0]  b2 = buf_after_refill[23:16];
    wire [11:0] d1 = {b1[3:0], b0};
    wire [11:0] d2 = {b2,       b1[7:4]};

    wire valid_d1     = (d1 < KYBER_Q);
    wire valid_d2     = (d2 < KYBER_Q);
    wire space_for_2  = (coeff_count <= 9'd254);
    wire space_for_1  = (coeff_count <= 9'd255);

    wire have_3_after_refill = (cnt_after_refill >= 5'd3);
    wire consume_now = (state == RUN) && have_3_after_refill && (coeff_count < 9'd256);

    // After consume: shift buf down by 24 bits, decrement count by 3.
    wire [127:0] buf_after_consume = consume_now
                                     ? (buf_after_refill >> 24)
                                     : buf_after_refill;
    wire [4:0]   cnt_after_consume = consume_now
                                     ? (cnt_after_refill - 5'd3)
                                     : cnt_after_refill;

    always @(posedge clk) begin
        if (!rst_n) begin
            state            <= IDLE;
            byte_buf         <= 128'd0;
            byte_count       <= 5'd0;
            coeff_count      <= 9'd0;
            ram_we_a0        <= 1'b0;
            ram_we_a1        <= 1'b0;
            ram_addr         <= 7'd0;
            ram_ptr          <= 7'd0;
            ram_a0_din       <= 16'd0;
            ram_a1_din       <= 16'd0;
            done             <= 1'b0;
            pending_d2       <= 12'd0;
            pending_d2_valid <= 1'b0;
        end else begin
            ram_we_a0 <= 1'b0;
            ram_we_a1 <= 1'b0;
            done      <= 1'b0;

            // Buffer + count update — covers refill, consume, both, neither.
            byte_buf   <= buf_after_consume;
            byte_count <= cnt_after_consume;

            case (state)
                IDLE: begin
                    if (start) begin
                        coeff_count      <= 9'd0;
                        ram_ptr          <= 7'd0;
                        byte_count       <= 5'd0;
                        byte_buf         <= 128'd0;
                        pending_d2       <= 12'd0;
                        pending_d2_valid <= 1'b0;
                        state            <= RUN;
                    end
                end

                RUN: begin
                    if (coeff_count >= 9'd256) begin
                        done  <= 1'b1;
                        state <= IDLE;
                    end else if (consume_now) begin
                        // Parse + write (uses pre-shift buffer view via d1/d2)
                        if (valid_d1 && valid_d2 && space_for_2) begin
                            if (coeff_count[0] == 1'b0) begin
                                ram_addr    <= ram_ptr;
                                ram_we_a0   <= 1'b1;
                                ram_a0_din  <= {4'd0, d1};
                                ram_we_a1   <= 1'b1;
                                ram_a1_din  <= {4'd0, d2};
                                coeff_count <= coeff_count + 9'd2;
                                ram_ptr     <= ram_ptr + 7'd1;
                            end else begin
                                ram_addr         <= ram_ptr;
                                ram_we_a1        <= 1'b1;
                                ram_a1_din       <= {4'd0, d1};
                                coeff_count      <= coeff_count + 9'd1;
                                ram_ptr          <= ram_ptr + 7'd1;
                                pending_d2       <= d2;
                                pending_d2_valid <= 1'b1;
                                state            <= FLUSH_D2;
                            end
                        end else if (valid_d1 && space_for_1) begin
                            if (coeff_count[0] == 1'b0) begin
                                ram_addr    <= ram_ptr;
                                ram_we_a0   <= 1'b1;
                                ram_a0_din  <= {4'd0, d1};
                                coeff_count <= coeff_count + 9'd1;
                            end else begin
                                ram_addr    <= ram_ptr;
                                ram_we_a1   <= 1'b1;
                                ram_a1_din  <= {4'd0, d1};
                                coeff_count <= coeff_count + 9'd1;
                                ram_ptr     <= ram_ptr + 7'd1;
                            end
                        end else if (valid_d2 && space_for_1) begin
                            if (coeff_count[0] == 1'b0) begin
                                ram_addr    <= ram_ptr;
                                ram_we_a0   <= 1'b1;
                                ram_a0_din  <= {4'd0, d2};
                                coeff_count <= coeff_count + 9'd1;
                            end else begin
                                ram_addr    <= ram_ptr;
                                ram_we_a1   <= 1'b1;
                                ram_a1_din  <= {4'd0, d2};
                                coeff_count <= coeff_count + 9'd1;
                                ram_ptr     <= ram_ptr + 7'd1;
                            end
                        end
                        // else: both rejected — bytes still consumed
                    end
                    // else: consume_now=0 (waiting for refill) — buf/cnt
                    //       updated above, no parse this cycle
                end

                FLUSH_D2: begin
                    if (pending_d2_valid) begin
                        ram_addr         <= ram_ptr;
                        ram_we_a0        <= 1'b1;
                        ram_a0_din       <= {4'd0, pending_d2};
                        coeff_count      <= coeff_count + 9'd1;
                        pending_d2_valid <= 1'b0;
                    end
                    state <= RUN;
                end

                default: state <= IDLE;
            endcase
        end
    end

endmodule
