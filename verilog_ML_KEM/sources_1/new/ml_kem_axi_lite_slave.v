`timescale 1ns / 1ps

module ml_kem_axi_lite_slave #
(
    parameter integer C_S_AXI_ADDR_WIDTH = 8,
    parameter integer C_S_AXI_DATA_WIDTH = 32
)
(
    input  wire                               aclk,
    input  wire                               aresetn,

    input  wire [C_S_AXI_ADDR_WIDTH-1:0]      s_axi_awaddr,
    input  wire                               s_axi_awvalid,
    output reg                                s_axi_awready,
    input  wire [C_S_AXI_DATA_WIDTH-1:0]      s_axi_wdata,
    input  wire [(C_S_AXI_DATA_WIDTH/8)-1:0]  s_axi_wstrb,
    input  wire                               s_axi_wvalid,
    output reg                                s_axi_wready,
    output reg  [1:0]                         s_axi_bresp,
    output reg                                s_axi_bvalid,
    input  wire                               s_axi_bready,

    input  wire [C_S_AXI_ADDR_WIDTH-1:0]      s_axi_araddr,
    input  wire                               s_axi_arvalid,
    output reg                                s_axi_arready,
    output reg [C_S_AXI_DATA_WIDTH-1:0]       s_axi_rdata,
    output reg [1:0]                          s_axi_rresp,
    output reg                                s_axi_rvalid,
    input  wire                               s_axi_rready,

    input  wire                               status_done,
    input  wire                               status_idle,
    input  wire                               status_error,
    input  wire [31:0]                        cycles_count,

    output reg                                start_pulse,
    output reg [1:0]                          op_sel,
    output reg [255:0]                        seed_d,
    output reg [255:0]                        seed_z,
    output reg [31:0]                         pk_addr,
    output reg [31:0]                         sk_addr,
    output reg [31:0]                         ct_addr,
    output reg [31:0]                         ss_addr,
    output reg [31:0]                         m_addr,
    // R-new-D K3 (Method E batched API): outer-loop count for KeyGen.
    // batch_count = 1 → single op (existing behavior). batch_count > 1 →
    // outer FSM repeats KeyGen N times, advancing pk/sk DDR offsets per
    // iteration. Same AXI-Lite seed_d/seed_z used for all iterations in
    // Phase A (Phase B = DDR-sourced seeds, future work).
    output reg [31:0]                         batch_count
);

    localparam [7:0] REG_CTRL      = 8'h00;
    localparam [7:0] REG_STATUS    = 8'h04;
    localparam [7:0] REG_CYCLES    = 8'h08;
    localparam [7:0] REG_SEED_D_0  = 8'h10;
    localparam [7:0] REG_SEED_D_7  = 8'h2C;
    localparam [7:0] REG_SEED_Z_0  = 8'h30;
    localparam [7:0] REG_SEED_Z_7  = 8'h4C;
    localparam [7:0] REG_PK_ADDR   = 8'h50;
    localparam [7:0] REG_SK_ADDR   = 8'h54;
    localparam [7:0] REG_CT_ADDR   = 8'h58;
    localparam [7:0] REG_SS_ADDR   = 8'h5C;
    localparam [7:0] REG_M_ADDR    = 8'h60;
    // R-new-D K3: batched API
    localparam [7:0] REG_BATCH_COUNT = 8'h64;

    reg aw_hs_seen;
    reg w_hs_seen;
    reg [C_S_AXI_ADDR_WIDTH-1:0] awaddr_lat;
    reg [C_S_AXI_DATA_WIDTH-1:0] wdata_lat;
    reg [(C_S_AXI_DATA_WIDTH/8)-1:0] wstrb_lat;

    reg [C_S_AXI_ADDR_WIDTH-1:0] araddr_lat;

    wire wr_fire = aw_hs_seen && w_hs_seen && !s_axi_bvalid;
    wire [7:0] wr_addr = {awaddr_lat[7:2], 2'b00};
    wire [7:0] rd_addr = {araddr_lat[7:2], 2'b00};

    integer i;
    always @(posedge aclk) begin
        if (!aresetn) begin
            s_axi_awready <= 1'b1;
            s_axi_wready  <= 1'b1;
            s_axi_bresp   <= 2'b00;
            s_axi_bvalid  <= 1'b0;
            s_axi_arready <= 1'b1;
            s_axi_rdata   <= {C_S_AXI_DATA_WIDTH{1'b0}};
            s_axi_rresp   <= 2'b00;
            s_axi_rvalid  <= 1'b0;

            aw_hs_seen    <= 1'b0;
            w_hs_seen     <= 1'b0;
            awaddr_lat    <= {C_S_AXI_ADDR_WIDTH{1'b0}};
            wdata_lat     <= {C_S_AXI_DATA_WIDTH{1'b0}};
            wstrb_lat     <= {(C_S_AXI_DATA_WIDTH/8){1'b0}};
            araddr_lat    <= {C_S_AXI_ADDR_WIDTH{1'b0}};

            start_pulse   <= 1'b0;
            op_sel        <= 2'd0;
            seed_d        <= 256'd0;
            seed_z        <= 256'd0;
            pk_addr       <= 32'd0;
            sk_addr       <= 32'd0;
            ct_addr       <= 32'd0;
            ss_addr       <= 32'd0;
            m_addr        <= 32'd0;
            batch_count   <= 32'd1;
        end else begin
            start_pulse <= 1'b0;

            if (s_axi_awready && s_axi_awvalid) begin
                aw_hs_seen <= 1'b1;
                awaddr_lat <= s_axi_awaddr;
                s_axi_awready <= 1'b0;
            end
            if (s_axi_wready && s_axi_wvalid) begin
                w_hs_seen <= 1'b1;
                wdata_lat <= s_axi_wdata;
                wstrb_lat <= s_axi_wstrb;
                s_axi_wready <= 1'b0;
            end

            if (wr_fire) begin
                s_axi_bvalid <= 1'b1;
                s_axi_bresp  <= 2'b00;

                case (wr_addr)
                    REG_CTRL: begin
                        if (wstrb_lat[0]) begin
                            op_sel <= wdata_lat[2:1];
                            if (wdata_lat[0]) begin
                                start_pulse <= 1'b1;
                            end
                        end
                    end

                    REG_SEED_D_0, 8'h14, 8'h18, 8'h1C, 8'h20, 8'h24, 8'h28, REG_SEED_D_7: begin
                        for (i = 0; i < 4; i = i + 1) begin
                            if (wstrb_lat[i]) begin
                                seed_d[((wr_addr - REG_SEED_D_0) + i)*8 +: 8] <= wdata_lat[i*8 +: 8];
                            end
                        end
                    end

                    REG_SEED_Z_0, 8'h34, 8'h38, 8'h3C, 8'h40, 8'h44, 8'h48, REG_SEED_Z_7: begin
                        for (i = 0; i < 4; i = i + 1) begin
                            if (wstrb_lat[i]) begin
                                seed_z[((wr_addr - REG_SEED_Z_0) + i)*8 +: 8] <= wdata_lat[i*8 +: 8];
                            end
                        end
                    end

                    REG_PK_ADDR: begin
                        for (i = 0; i < 4; i = i + 1) begin
                            if (wstrb_lat[i]) pk_addr[i*8 +: 8] <= wdata_lat[i*8 +: 8];
                        end
                    end

                    REG_SK_ADDR: begin
                        for (i = 0; i < 4; i = i + 1) begin
                            if (wstrb_lat[i]) sk_addr[i*8 +: 8] <= wdata_lat[i*8 +: 8];
                        end
                    end

                    REG_CT_ADDR: begin
                        for (i = 0; i < 4; i = i + 1) begin
                            if (wstrb_lat[i]) ct_addr[i*8 +: 8] <= wdata_lat[i*8 +: 8];
                        end
                    end

                    REG_SS_ADDR: begin
                        for (i = 0; i < 4; i = i + 1) begin
                            if (wstrb_lat[i]) ss_addr[i*8 +: 8] <= wdata_lat[i*8 +: 8];
                        end
                    end

                    REG_M_ADDR: begin
                        for (i = 0; i < 4; i = i + 1) begin
                            if (wstrb_lat[i]) m_addr[i*8 +: 8] <= wdata_lat[i*8 +: 8];
                        end
                    end

                    REG_BATCH_COUNT: begin
                        for (i = 0; i < 4; i = i + 1) begin
                            if (wstrb_lat[i]) batch_count[i*8 +: 8] <= wdata_lat[i*8 +: 8];
                        end
                    end

                    default: begin
                    end
                endcase
            end

            if (s_axi_bvalid && s_axi_bready) begin
                s_axi_bvalid  <= 1'b0;
                aw_hs_seen    <= 1'b0;
                w_hs_seen     <= 1'b0;
                s_axi_awready <= 1'b1;
                s_axi_wready  <= 1'b1;
            end

            if (s_axi_arready && s_axi_arvalid) begin
                araddr_lat    <= s_axi_araddr;
                s_axi_arready <= 1'b0;
                s_axi_rvalid  <= 1'b1;
                s_axi_rresp   <= 2'b00;

                case ({s_axi_araddr[7:2], 2'b00})
                    REG_CTRL: begin
                        s_axi_rdata <= {29'd0, op_sel, 1'b0};
                    end
                    REG_STATUS: begin
                        s_axi_rdata <= {29'd0, status_error, status_idle, status_done};
                    end
                    REG_CYCLES: begin
                        s_axi_rdata <= cycles_count;
                    end
                    REG_SEED_D_0, 8'h14, 8'h18, 8'h1C, 8'h20, 8'h24, 8'h28, REG_SEED_D_7: begin
                        s_axi_rdata <= {
                            seed_d[((({s_axi_araddr[7:2], 2'b00} - REG_SEED_D_0) + 3) * 8) +: 8],
                            seed_d[((({s_axi_araddr[7:2], 2'b00} - REG_SEED_D_0) + 2) * 8) +: 8],
                            seed_d[((({s_axi_araddr[7:2], 2'b00} - REG_SEED_D_0) + 1) * 8) +: 8],
                            seed_d[((({s_axi_araddr[7:2], 2'b00} - REG_SEED_D_0) + 0) * 8) +: 8]
                        };
                    end
                    REG_SEED_Z_0, 8'h34, 8'h38, 8'h3C, 8'h40, 8'h44, 8'h48, REG_SEED_Z_7: begin
                        s_axi_rdata <= {
                            seed_z[((({s_axi_araddr[7:2], 2'b00} - REG_SEED_Z_0) + 3) * 8) +: 8],
                            seed_z[((({s_axi_araddr[7:2], 2'b00} - REG_SEED_Z_0) + 2) * 8) +: 8],
                            seed_z[((({s_axi_araddr[7:2], 2'b00} - REG_SEED_Z_0) + 1) * 8) +: 8],
                            seed_z[((({s_axi_araddr[7:2], 2'b00} - REG_SEED_Z_0) + 0) * 8) +: 8]
                        };
                    end
                    REG_PK_ADDR: s_axi_rdata <= pk_addr;
                    REG_SK_ADDR: s_axi_rdata <= sk_addr;
                    REG_CT_ADDR: s_axi_rdata <= ct_addr;
                    REG_SS_ADDR: s_axi_rdata <= ss_addr;
                    REG_M_ADDR:  s_axi_rdata <= m_addr;
                    REG_BATCH_COUNT: s_axi_rdata <= batch_count;
                    default:     s_axi_rdata <= 32'd0;
                endcase
            end

            if (s_axi_rvalid && s_axi_rready) begin
                s_axi_rvalid  <= 1'b0;
                s_axi_arready <= 1'b1;
            end
        end
    end

endmodule
