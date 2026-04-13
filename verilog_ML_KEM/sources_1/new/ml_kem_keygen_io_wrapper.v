`timescale 1ns / 1ps

module ml_kem_keygen_io_wrapper (
    input  wire        clk,
    input  wire        rst_n,

    input  wire        start,
    output reg         busy,
    output reg         done,

    // Seed write interface (byte-level)
    input  wire        seed_we,
    input  wire        seed_sel,   // 0: seed_d, 1: seed_z
    input  wire [4:0]  seed_addr,
    input  wire [7:0]  seed_wdata,

    // Output read interface (byte-level)
    input  wire        out_rd,
    input  wire        out_sel,    // 0: pk, 1: sk
    input  wire [11:0] out_addr,
    output reg  [7:0]  out_rdata,
    output reg         out_valid
);

    reg [255:0] seed_d_reg;
    reg [255:0] seed_z_reg;

    wire        core_done;
    wire        pk_we;
    wire [10:0] pk_addr;
    wire [7:0]  pk_dout;
    wire        sk_we;
    wire [11:0] sk_addr;
    wire [7:0]  sk_dout;

    reg         core_start;

    reg [7:0] pk_mem [0:1183];
    reg [7:0] sk_mem [0:2399];

    ml_kem_keygen u_core (
        .clk(clk),
        .rst_n(rst_n),
        .start(core_start),
        .done(core_done),
        .seed_d_in(seed_d_reg),
        .seed_z_in(seed_z_reg),
        .pk_we(pk_we),
        .pk_addr(pk_addr),
        .pk_dout(pk_dout),
        .sk_we(sk_we),
        .sk_addr(sk_addr),
        .sk_dout(sk_dout)
    );

    integer i;
    always @(posedge clk) begin
        if (!rst_n) begin
            busy <= 1'b0;
            done <= 1'b0;
            core_start <= 1'b0;
            out_rdata <= 8'd0;
            out_valid <= 1'b0;
            seed_d_reg <= 256'd0;
            seed_z_reg <= 256'd0;
            for (i = 0; i < 1184; i = i + 1) pk_mem[i] <= 8'd0;
            for (i = 0; i < 2400; i = i + 1) sk_mem[i] <= 8'd0;
        end else begin
            core_start <= 1'b0;
            out_valid <= 1'b0;

            if (seed_we && !busy) begin
                if (!seed_sel) seed_d_reg[seed_addr*8 +: 8] <= seed_wdata;
                else           seed_z_reg[seed_addr*8 +: 8] <= seed_wdata;
            end

            if (start && !busy) begin
                busy <= 1'b1;
                done <= 1'b0;
                core_start <= 1'b1;
            end

            if (pk_we && (pk_addr < 11'd1184)) begin
                pk_mem[pk_addr] <= pk_dout;
            end

            if (sk_we && (sk_addr < 12'd2400)) begin
                sk_mem[sk_addr] <= sk_dout;
            end

            if (core_done) begin
                busy <= 1'b0;
                done <= 1'b1;
            end

            if (out_rd) begin
                if (!out_sel) begin
                    if (out_addr < 12'd1184) out_rdata <= pk_mem[out_addr[10:0]];
                    else                     out_rdata <= 8'd0;
                end else begin
                    if (out_addr < 12'd2400) out_rdata <= sk_mem[out_addr];
                    else                     out_rdata <= 8'd0;
                end
                out_valid <= 1'b1;
            end
        end
    end

endmodule
