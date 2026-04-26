`timescale 1ns / 1ps

module kpke_core #(
    parameter HAS_INTERNAL_ENCRYPT = 1
) (
    input  wire         clk,
    input  wire         rst_n,

    // Control
    input  wire         start,
    input  wire [1:0]   mode,        // 00 = DECRYPT, 01 = ENCRYPT
    output wire         busy,
    output wire         done,

    // Byte preload input
    input  wire         in_we,
    input  wire [1:0]   in_sel,      // in_sel mapping depends on mode:
                                     // mode=DECRYPT: 00=dk_PKE, 01=ct, 10/11=unused
                                     // mode=ENCRYPT: 00=ek,     01=m,  10=r, 11=unused

    input  wire [10:0]  in_addr,
    input  wire [7:0]   in_wdata,

    // DECRYPT output (valid when mode=DECRYPT, done=1)
    output wire [255:0] m_out,

    // ENCRYPT streaming output
    output wire         ct_we,
    output wire [10:0]  ct_addr,
    output wire [7:0]   ct_dout,

    // Reserved shared-keccak interface (only meaningful when HAS_INTERNAL_ENCRYPT=1)
    output wire         k_init,
    output wire [1:0]   k_hash_type,
    output wire         k_finalize,
    output wire [7:0]   k_din,
    output wire         k_din_valid,
    input  wire         k_din_ready,
    input  wire [7:0]   k_dout,
    input  wire         k_dout_valid,
    output wire         k_dout_ready,

    // External kpke_encrypt interface (only used when HAS_INTERNAL_ENCRYPT == 0).
    // Forward signals: parent drives encrypt instance via these outputs.
    output wire         ext_enc_start,
    output wire         ext_enc_in_we,
    output wire [1:0]   ext_enc_in_sel,
    output wire [10:0]  ext_enc_in_addr,
    output wire [7:0]   ext_enc_in_wdata,
    // Backward signals: parent reads encrypt instance status via these inputs.
    input  wire         ext_enc_busy,
    input  wire         ext_enc_done,
    input  wire         ext_enc_ct_we,
    input  wire [10:0]  ext_enc_ct_addr,
    input  wire [7:0]   ext_enc_ct_dout
);

    localparam [1:0] MODE_DECRYPT = 2'b00;
    localparam [1:0] MODE_ENCRYPT = 2'b01;

    reg [1:0] active_mode;
    reg       dec_start_r;
    reg       enc_start_r;

    wire cfg_mode_dec = (mode == MODE_DECRYPT);
    wire cfg_mode_enc = (mode == MODE_ENCRYPT);

    wire run_mode_dec = (active_mode == MODE_DECRYPT);
    wire run_mode_enc = (active_mode == MODE_ENCRYPT);

    wire dec_in_we = in_we && cfg_mode_dec;
    wire enc_in_we = in_we && cfg_mode_enc;

    wire dec_busy;
    wire dec_done;
    wire [255:0] dec_m_out;

    wire enc_busy;
    wire enc_done;
    wire enc_ct_we;
    wire [10:0] enc_ct_addr;
    wire [7:0]  enc_ct_dout;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            active_mode <= MODE_DECRYPT;
            dec_start_r <= 1'b0;
            enc_start_r <= 1'b0;
        end else begin
            dec_start_r <= start && cfg_mode_dec;
            enc_start_r <= start && cfg_mode_enc;

            if (start && !busy) begin
                active_mode <= mode;
            end
        end
    end

    kpke_decrypt u_decrypt (
        .clk(clk),
        .rst_n(rst_n),
        .start(dec_start_r),
        .busy(dec_busy),
        .done(dec_done),
        .in_we(dec_in_we),
        .in_sel(in_sel[0]),
        .in_addr(in_addr),
        .in_wdata(in_wdata),
        .out_rd(1'b0),
        .out_addr(5'd0),
        .out_rdata(),
        .out_valid(),
        .msg_we(),
        .msg_addr(),
        .msg_dout(),
        .m_out(dec_m_out)
    );

    generate
        if (HAS_INTERNAL_ENCRYPT) begin : gen_int_encrypt
            // Local kpke_encrypt instance with externally-routed keccak (Gate 2.1+).
            kpke_encrypt #(
                .HAS_INTERNAL_KECCAK(0)
            ) u_encrypt (
                .clk(clk),
                .rst_n(rst_n),
                .start(enc_start_r),
                .busy(enc_busy),
                .done(enc_done),
                .in_we(enc_in_we),
                .in_sel(in_sel),
                .in_addr(in_addr),
                .in_wdata(in_wdata),
                .out_rd(1'b0),
                .out_addr(11'd0),
                .out_rdata(),
                .out_valid(),
                .ct_we(enc_ct_we),
                .ct_addr(enc_ct_addr),
                .ct_dout(enc_ct_dout),
                .ext_k_init(k_init),
                .ext_k_hash_type(k_hash_type),
                .ext_k_finalize(k_finalize),
                .ext_k_din(k_din),
                .ext_k_din_valid(k_din_valid),
                .ext_k_din_ready(k_din_ready),
                .ext_k_dout(k_dout),
                .ext_k_dout_valid(k_dout_valid),
                .ext_k_dout_ready(k_dout_ready)
            );

            assign ext_enc_start    = 1'b0;
            assign ext_enc_in_we    = 1'b0;
            assign ext_enc_in_sel   = 2'b00;
            assign ext_enc_in_addr  = 11'd0;
            assign ext_enc_in_wdata = 8'd0;
        end else begin : gen_ext_encrypt
            // No local kpke_encrypt — drive shared encrypt instance via ext_enc_*.
            // Bring back its status for the local FSM via inputs.
            assign ext_enc_start    = enc_start_r;
            assign ext_enc_in_we    = enc_in_we;
            assign ext_enc_in_sel   = in_sel;
            assign ext_enc_in_addr  = in_addr;
            assign ext_enc_in_wdata = in_wdata;

            assign enc_busy    = ext_enc_busy;
            assign enc_done    = ext_enc_done;
            assign enc_ct_we   = ext_enc_ct_we;
            assign enc_ct_addr = ext_enc_ct_addr;
            assign enc_ct_dout = ext_enc_ct_dout;

            // Keccak ports tied to inert: shared encrypt instance owns keccak
            // directly via its own ext_k_* path at the top level.
            assign k_init       = 1'b0;
            assign k_hash_type  = 2'b00;
            assign k_finalize   = 1'b0;
            assign k_din        = 8'd0;
            assign k_din_valid  = 1'b0;
            assign k_dout_ready = 1'b0;
        end
    endgenerate

    assign busy = run_mode_dec ? dec_busy :
                  run_mode_enc ? enc_busy : 1'b0;
    assign done = run_mode_dec ? dec_done :
                  run_mode_enc ? enc_done : 1'b0;

    assign m_out   = dec_m_out;
    assign ct_we   = run_mode_enc ? enc_ct_we : 1'b0;
    assign ct_addr = enc_ct_addr;
    assign ct_dout = enc_ct_dout;

endmodule
