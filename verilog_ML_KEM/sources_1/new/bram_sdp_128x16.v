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

// R-new-A Phase E1: 1R1W BRAM with byte-resolution writes (PS-side AXI
// preload) and 64-bit lane-wide reads (Keccak lane absorb feed). Symmetric
// 64-bit ports with 8-bit byte-strobe write enables — same Vivado-friendly
// pattern as xpm_ram_sdp_word_bs but at lane width. Caller passes byte
// address + 8-bit data; this wrapper handles the lane/byte split internally
// (lane addr = wr_addr[10:3], byte mask = 1-hot at wr_addr[2:0]).
//
// Address conventions:
//   wr_addr      — byte address [BYTE_ADDR_WIDTH-1:0]   (caller-facing)
//   rd_lane_addr — lane address [BYTE_ADDR_WIDTH-4:0]  (= byte_addr / 8)
module xpm_ram_sdp_byte_write_lane_read #(
    parameter integer BYTE_ADDR_WIDTH = 11,
    parameter integer DEPTH_BYTES     = 1 << BYTE_ADDR_WIDTH,
    parameter integer READ_LATENCY    = 1
)(
    input  wire                          clk,
    // Port A: byte-resolution write at byte address (caller-facing API)
    input  wire                          wr_en,
    input  wire [BYTE_ADDR_WIDTH-1:0]    wr_addr,
    input  wire [7:0]                    wr_data,
    // Port B: lane read (64-bit) at lane address
    input  wire                          rd_en,
    input  wire [BYTE_ADDR_WIDTH-4:0]    rd_lane_addr,
    output wire [63:0]                   rd_lane_data
);

    // Lane addr + byte position split
    wire [BYTE_ADDR_WIDTH-4:0] wr_lane_addr = wr_addr[BYTE_ADDR_WIDTH-1:3];
    wire [2:0]                 wr_byte_pos  = wr_addr[2:0];
    // 1-hot byte enable mask (8 bits = 1 bit per byte in 64-bit lane)
    wire [7:0]                 wr_byte_mask = wr_en ? (8'b1 << wr_byte_pos) : 8'b0;
    // Replicate wr_data across all 8 byte positions; only the enabled byte
    // (selected by wr_byte_mask) actually writes.
    wire [63:0]                wr_lane_data = {8{wr_data}};

    xpm_memory_sdpram #(
        .ADDR_WIDTH_A        (BYTE_ADDR_WIDTH-3),
        .ADDR_WIDTH_B        (BYTE_ADDR_WIDTH-3),
        .AUTO_SLEEP_TIME     (0),
        .BYTE_WRITE_WIDTH_A  (8),
        .CASCADE_HEIGHT      (0),
        .CLOCKING_MODE       ("common_clock"),
        .ECC_MODE            ("no_ecc"),
        .MEMORY_INIT_FILE    ("none"),
        .MEMORY_INIT_PARAM   ("0"),
        .MEMORY_OPTIMIZATION ("true"),
        .MEMORY_PRIMITIVE    ("block"),
        .MEMORY_SIZE         (DEPTH_BYTES * 8),
        .MESSAGE_CONTROL     (0),
        .READ_DATA_WIDTH_B   (64),
        .READ_LATENCY_B      (READ_LATENCY),
        .READ_RESET_VALUE_B  ("0"),
        .RST_MODE_A          ("SYNC"),
        .RST_MODE_B          ("SYNC"),
        .SIM_ASSERT_CHK      (0),
        .USE_EMBEDDED_CONSTRAINT (0),
        .USE_MEM_INIT        (0),
        .WAKEUP_TIME         ("disable_sleep"),
        .WRITE_DATA_WIDTH_A  (64),
        .WRITE_MODE_B        ("no_change")
    ) u_ram (
        .dbiterrb      (),
        .doutb         (rd_lane_data),
        .sbiterrb      (),
        .addra         (wr_lane_addr),
        .addrb         (rd_lane_addr),
        .clka          (clk),
        .clkb          (clk),
        .dina          (wr_lane_data),
        .ena           (|wr_byte_mask),
        .enb           (rd_en),
        .injectdbiterra(1'b0),
        .injectsbiterra(1'b0),
        .regceb        (1'b1),
        .rstb          (1'b0),
        .sleep         (1'b0),
        .wea           (wr_byte_mask)
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
