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

// Generic byte-addressed 1R1W BRAM wrapper using XPM.
module xpm_ram_sdp_byte #(
    parameter integer ADDR_WIDTH = 11,
    parameter integer DEPTH = (1 << ADDR_WIDTH),
    parameter integer READ_LATENCY = 1
)(
    input  wire                  clk,
    input  wire                  wr_en,
    input  wire [ADDR_WIDTH-1:0] wr_addr,
    input  wire [7:0]            wr_data,
    input  wire                  rd_en,
    input  wire [ADDR_WIDTH-1:0] rd_addr,
    output wire [7:0]            rd_data
);

    xpm_memory_sdpram #(
        .ADDR_WIDTH_A        (ADDR_WIDTH),
        .ADDR_WIDTH_B        (ADDR_WIDTH),
        .AUTO_SLEEP_TIME     (0),
        .BYTE_WRITE_WIDTH_A  (8),
        .CASCADE_HEIGHT      (0),
        .CLOCKING_MODE       ("common_clock"),
        .ECC_MODE            ("no_ecc"),
        .MEMORY_INIT_FILE    ("none"),
        .MEMORY_INIT_PARAM   ("0"),
        .MEMORY_OPTIMIZATION ("true"),
        .MEMORY_PRIMITIVE    ("block"),
        .MEMORY_SIZE         (DEPTH * 8),
        .MESSAGE_CONTROL     (0),
        .READ_DATA_WIDTH_B   (8),
        .READ_LATENCY_B      (READ_LATENCY),
        .READ_RESET_VALUE_B  ("0"),
        .RST_MODE_A          ("SYNC"),
        .RST_MODE_B          ("SYNC"),
        .SIM_ASSERT_CHK      (0),
        .USE_EMBEDDED_CONSTRAINT (0),
        .USE_MEM_INIT        (0),
        .WAKEUP_TIME         ("disable_sleep"),
        .WRITE_DATA_WIDTH_A  (8),
        .WRITE_MODE_B        ("no_change")
    ) u_ram (
        .dbiterrb      (),
        .doutb         (rd_data),
        .sbiterrb      (),
        .addra         (wr_addr),
        .addrb         (rd_addr),
        .clka          (clk),
        .clkb          (clk),
        .dina          (wr_data),
        .ena           (wr_en),
        .enb           (rd_en),
        .injectdbiterra(1'b0),
        .injectsbiterra(1'b0),
        .regceb        (1'b1),
        .rstb          (1'b0),
        .sleep         (1'b0),
        .wea           (wr_en)
    );

endmodule

// 32-bit word-wide 1R1W BRAM wrapper with byte-strobe writes.
// Lets a single physical BRAM serve both AXI 32-bit word transfers and
// byte-level writes from crypto cores (via wr_be mask).
module xpm_ram_sdp_word_bs #(
    parameter integer ADDR_WIDTH   = 9,
    parameter integer DEPTH        = (1 << ADDR_WIDTH),
    parameter integer READ_LATENCY = 1
)(
    input  wire                  clk,
    // Write port (word address, byte-enable)
    input  wire [3:0]            wr_be,
    input  wire [ADDR_WIDTH-1:0] wr_addr,
    input  wire [31:0]           wr_data,
    // Read port (word)
    input  wire                  rd_en,
    input  wire [ADDR_WIDTH-1:0] rd_addr,
    output wire [31:0]           rd_data
);

    xpm_memory_sdpram #(
        .ADDR_WIDTH_A        (ADDR_WIDTH),
        .ADDR_WIDTH_B        (ADDR_WIDTH),
        .AUTO_SLEEP_TIME     (0),
        .BYTE_WRITE_WIDTH_A  (8),
        .CASCADE_HEIGHT      (0),
        .CLOCKING_MODE       ("common_clock"),
        .ECC_MODE            ("no_ecc"),
        .MEMORY_INIT_FILE    ("none"),
        .MEMORY_INIT_PARAM   ("0"),
        .MEMORY_OPTIMIZATION ("true"),
        .MEMORY_PRIMITIVE    ("block"),
        .MEMORY_SIZE         (DEPTH * 32),
        .MESSAGE_CONTROL     (0),
        .READ_DATA_WIDTH_B   (32),
        .READ_LATENCY_B      (READ_LATENCY),
        .READ_RESET_VALUE_B  ("0"),
        .RST_MODE_A          ("SYNC"),
        .RST_MODE_B          ("SYNC"),
        .SIM_ASSERT_CHK      (0),
        .USE_EMBEDDED_CONSTRAINT (0),
        .USE_MEM_INIT        (0),
        .WAKEUP_TIME         ("disable_sleep"),
        .WRITE_DATA_WIDTH_A  (32),
        .WRITE_MODE_B        ("no_change")
    ) u_ram (
        .dbiterrb      (),
        .doutb         (rd_data),
        .sbiterrb      (),
        .addra         (wr_addr),
        .addrb         (rd_addr),
        .clka          (clk),
        .clkb          (clk),
        .dina          (wr_data),
        .ena           (|wr_be),
        .enb           (rd_en),
        .injectdbiterra(1'b0),
        .injectsbiterra(1'b0),
        .regceb        (1'b1),
        .rstb          (1'b0),
        .sleep         (1'b0),
        .wea           (wr_be)
    );

endmodule
