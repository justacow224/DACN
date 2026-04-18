`timescale 1ns / 1ps

// Simple dual-port RAM wrapper (1R1W, common clock) for explicit BRAM intent.
// Read latency: 1 cycle.
module bram_sdp_128x16 (
    input  wire        clk,
    input  wire        rst_n,
    input  wire [6:0]  raddr,
    input  wire [6:0]  waddr,
    input  wire        we,
    input  wire [15:0] din,
    output wire [15:0] dout
);

    (* ram_style = "block" *) reg [15:0] mem [0:127];
    reg [15:0] dout_reg;

    always @(posedge clk) begin
        if (!rst_n) begin
            dout_reg <= 16'd0;
        end else begin
            dout_reg <= mem[raddr];
            if (we) begin
                mem[waddr] <= din;
            end
        end
    end

    assign dout = dout_reg;

endmodule
