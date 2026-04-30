`timescale 1ns / 1ps

// Step 3.K1: sponge state buffer (state_reg[0:199] = 1,600 FF) removed.
// All sponge byte operations now go directly to keccak_f1600_core's A array
// via the new byte-XOR/byte-read interface (init/xor_we/xor_byte_addr/
// xor_byte_data/byte_dout). Padding (originally one combined parallel byte
// write) is now sequenced over two cycles (PAD_DOMAIN → PAD_LAST), adding
// one cycle to each finalize but saving 1,600 FF + the 1600-bit state_reg
// flat-mux feeding the core's state_in input (~300-600 LUT).

module keccak_sponge_top (
    input  wire         clk,
    input  wire         rst_n,

    // Control Interface
    input  wire         init,
    input  wire [1:0]   hash_type,
    input  wire         finalize,
    // R-new-A Phase B: latched on init. 0 = byte absorb (legacy din path),
    // 1 = lane absorb (new lane_din path, 8 bytes/cycle). Caller must use
    // a single mode for the entire absorb session up to finalize. Padding
    // and squeeze stay byte-level in Phase B (squeeze becomes lane in C).
    input  wire         absorb_lane_mode,

    // Data Input — byte path (legacy)
    input  wire [7:0]   din,
    input  wire         din_valid,
    output wire         din_ready,

    // R-new-A Phase B: lane absorb path. lane_din carries one 64-bit lane
    // per cycle; lane_din_ready asserts only when the FSM is in
    // ST_ABSORB_LANE and finalize hasn't fired. Caller must feed exactly
    // (msg_len_bytes / 8) lanes — non-multiple-of-8 messages still need
    // the byte path.
    input  wire [63:0]  lane_din,
    input  wire         lane_din_valid,
    output wire         lane_din_ready,

    // Data Output
    output wire [7:0]   dout,
    output wire         dout_valid,
    input  wire         dout_ready
);

    wire [7:0] rate = (hash_type == 2'b00) ? 8'd168 :
                      (hash_type == 2'b01) ? 8'd136 :
                      (hash_type == 2'b10) ? 8'd136 : 8'd72;

    wire [7:0] domain_pad = (hash_type == 2'b00 || hash_type == 2'b01) ? 8'h1F : 8'h06;

    reg  [7:0] byte_idx;

    // Core handshake signals
    reg         core_start;
    wire        core_done;

    // Step 3.K1: byte-level absorb/squeeze interface to core. Driven
    // combinationally from state below.
    reg         core_init;
    reg         core_xor_we;
    reg  [7:0]  core_xor_byte_addr;
    reg  [7:0]  core_xor_byte_data;
    wire [7:0]  core_byte_dout;

    // R-new-A Phase B: lane-level absorb interface to core. core_xor_lane_*
    // are driven from ST_ABSORB_LANE state. mode_lane latches absorb_lane_mode
    // on init so transitions out of permute (ST_WAIT_ABSORB → ABSORB or
    // ABSORB_LANE) and out of init (ST_INIT → ABSORB or ABSORB_LANE) know
    // which path the caller picked.
    reg         core_xor_lane_we;
    reg  [4:0]  core_xor_lane_addr;
    reg  [63:0] core_xor_lane_data;
    reg         mode_lane;

    keccak_f1600_core u_keccak_core (
        .clk(clk),
        .rst_n(rst_n),
        .start(core_start),
        .load_on_start(1'b0),                  // sponge mode: keep A across start
        .state_in(1600'b0),                    // unused in sponge mode
        .init(core_init),
        .xor_we(core_xor_we),
        .xor_byte_addr(core_xor_byte_addr),
        .xor_byte_data(core_xor_byte_data),
        .byte_dout(core_byte_dout),
        // R-new-A Phase B: lane absorb path now driven from FSM. Phase C
        // will add a lane squeeze read using lane_dout — for now it stays
        // open and squeeze still uses byte_dout.
        .xor_lane_we(core_xor_lane_we),
        .xor_lane_addr(core_xor_lane_addr),
        .xor_lane_data(core_xor_lane_data),
        .lane_dout(),
        .state_out(),                          // unused — sponge accesses bytes only
        .done(core_done)
    );

    // Sponge FSM. ST_INIT is a 1-cycle pulse that drives core_init=1 to
    // clear A (replaces the previous parallel for-loop reset of state_reg).
    // ST_PAD_DOMAIN/ST_PAD_LAST sequence the two padding XORs that the
    // original code did in one cycle via parallel array writes.
    localparam ST_IDLE          = 4'd0;
    localparam ST_INIT          = 4'd1;
    localparam ST_ABSORB        = 4'd2;
    localparam ST_WAIT_ABSORB   = 4'd3;
    localparam ST_PAD_DOMAIN    = 4'd4;
    localparam ST_PAD_LAST      = 4'd5;
    localparam ST_WAIT_SQUEEZE  = 4'd6;
    localparam ST_SQUEEZE       = 4'd7;
    // R-new-A Phase B
    localparam ST_ABSORB_LANE   = 4'd8;

    reg [3:0] state;

    assign din_ready       = (state == ST_ABSORB)      && !finalize;
    assign lane_din_ready  = (state == ST_ABSORB_LANE) && !finalize;
    assign dout_valid      = (state == ST_SQUEEZE);
    assign dout            = core_byte_dout;        // combinational byte read of A at byte_idx

    // Combinational core-control signals based on current sponge state.
    // Defaults below ensure no spurious XOR or init pulses outside the
    // explicit absorb/pad/init phases.
    always @(*) begin
        core_init          = 1'b0;
        core_xor_we        = 1'b0;
        core_xor_byte_addr = byte_idx;          // default: byte_idx (used by absorb + squeeze read)
        core_xor_byte_data = 8'd0;
        // R-new-A Phase B: lane signals default to inactive
        core_xor_lane_we   = 1'b0;
        core_xor_lane_addr = byte_idx[7:3];     // lane index = byte_idx / 8
        core_xor_lane_data = 64'd0;

        case (state)
            ST_INIT: begin
                core_init = 1'b1;
            end

            ST_ABSORB: begin
                if (din_valid && din_ready) begin
                    core_xor_we        = 1'b1;
                    core_xor_byte_data = din;
                    // core_xor_byte_addr defaults to byte_idx
                end
            end

            ST_ABSORB_LANE: begin
                if (lane_din_valid && lane_din_ready) begin
                    core_xor_lane_we   = 1'b1;
                    core_xor_lane_addr = byte_idx[7:3];
                    core_xor_lane_data = lane_din;
                end
            end

            ST_PAD_DOMAIN: begin
                core_xor_we        = 1'b1;
                core_xor_byte_addr = byte_idx;
                core_xor_byte_data = domain_pad;
            end

            ST_PAD_LAST: begin
                core_xor_we        = 1'b1;
                core_xor_byte_addr = rate - 8'd1;
                core_xor_byte_data = 8'h80;
            end

            // ST_SQUEEZE: byte_dout combinationally returns A[byte_idx];
            // no XOR write needed. Defaults already set core_xor_byte_addr
            // to byte_idx and core_xor_we to 0.
            default: ;
        endcase
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            state      <= ST_IDLE;
            byte_idx   <= 0;
            core_start <= 0;
            mode_lane  <= 1'b0;
        end
        else if (init) begin
            state      <= ST_INIT;
            byte_idx   <= 0;
            core_start <= 0;
            mode_lane  <= absorb_lane_mode;     // R-new-A Phase B: latch on init
        end
        else begin
            case (state)
                ST_IDLE: begin
                    // Wait for init
                end

                ST_INIT: begin
                    // 1-cycle pulse: combinational core_init=1 has been driven
                    // for this cycle, A will be cleared at the next posedge.
                    // R-new-A Phase B: branch into byte or lane absorb based
                    // on the latched mode.
                    state <= mode_lane ? ST_ABSORB_LANE : ST_ABSORB;
                end

                ST_ABSORB: begin
                    if (finalize) begin
                        // Begin 2-cycle padding sequence (one extra cycle vs.
                        // the original parallel-write padding).
                        state <= ST_PAD_DOMAIN;
                    end
                    else if (din_valid && din_ready) begin
                        // Combinational core_xor_we is driving the XOR for this
                        // cycle; the byte will be applied to A at the next
                        // posedge. Advance byte_idx and trigger permutation
                        // when block is full.
                        if (byte_idx == rate - 1) begin
                            byte_idx   <= 0;
                            core_start <= 1;     // becomes 1 in next cycle
                            state      <= ST_WAIT_ABSORB;
                        end else begin
                            byte_idx <= byte_idx + 1;
                        end
                    end
                end

                ST_ABSORB_LANE: begin
                    // R-new-A Phase B: lane absorb path. Combinational
                    // core_xor_lane_we drives XOR of one full 64-bit lane
                    // per cycle; byte_idx advances by 8. When byte_idx
                    // reaches rate-8 (last lane of the block), trigger
                    // permutation. Padding (byte-level) still works because
                    // byte_idx is always a multiple of 8 in lane mode and
                    // points to the next-byte-to-absorb position.
                    if (finalize) begin
                        state <= ST_PAD_DOMAIN;
                    end
                    else if (lane_din_valid && lane_din_ready) begin
                        if (byte_idx == rate - 8'd8) begin
                            byte_idx   <= 0;
                            core_start <= 1;
                            state      <= ST_WAIT_ABSORB;
                        end else begin
                            byte_idx <= byte_idx + 8'd8;
                        end
                    end
                end

                ST_PAD_DOMAIN: begin
                    // domain_pad XOR has been driven this cycle; advance to
                    // PAD_LAST which XORs 0x80 at rate-1. If byte_idx ==
                    // rate-1 the two XORs land on the same byte, producing
                    // exactly (domain_pad ^ 0x80) — same as the original.
                    state <= ST_PAD_LAST;
                end

                ST_PAD_LAST: begin
                    // 0x80 XOR has been driven this cycle. Trigger
                    // permutation next cycle (start asserted, xor_we deasserts
                    // by entering WAIT_SQUEEZE which leaves it at default 0).
                    core_start <= 1;
                    state      <= ST_WAIT_SQUEEZE;
                end

                ST_WAIT_ABSORB: begin
                    core_start <= 0;
                    if (core_done) begin
                        // No state capture needed — A is the canonical state.
                        // R-new-A Phase B: return to whichever absorb mode
                        // the caller selected at init.
                        state <= mode_lane ? ST_ABSORB_LANE : ST_ABSORB;
                    end
                end

                ST_WAIT_SQUEEZE: begin
                    core_start <= 0;
                    if (core_done) begin
                        byte_idx <= 0;
                        state    <= ST_SQUEEZE;
                    end
                end

                ST_SQUEEZE: begin
                    // dout combinationally reads core_byte_dout at byte_idx.
                    if (dout_valid && dout_ready) begin
                        if (byte_idx == rate - 1) begin
                            byte_idx   <= 0;
                            core_start <= 1;
                            state      <= ST_WAIT_SQUEEZE;
                        end else begin
                            byte_idx <= byte_idx + 1;
                        end
                    end
                end

                default: state <= ST_IDLE;
            endcase
        end
    end

endmodule
