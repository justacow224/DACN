`timescale 1ns / 1ps

module poly_parse_inline_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    output reg          done,

    // SHAKE128 8-bit stream
    input  wire [7:0]   shake_dout,
    input  wire         shake_dout_valid,
    output wire         shake_dout_ready,

    // RAM write interface (pair-per-address)
    output reg          ram_we_a0,
    output reg          ram_we_a1,
    output reg  [6:0]   ram_addr,
    output reg  [15:0]  ram_a0_din,
    output reg  [15:0]  ram_a1_din
);

    localparam IDLE        = 3'd0;
    localparam GET_BYTE_0  = 3'd1;
    localparam GET_BYTE_1  = 3'd2;
    localparam GET_BYTE_2  = 3'd3;
    localparam PARSE_WRITE = 3'd4;
    localparam FLUSH_D2    = 3'd5;

    localparam [11:0] KYBER_Q = 12'd3329;

    reg [2:0] state;
    reg [8:0] coeff_count;

    reg [7:0]  byte_reg0, byte_reg1, byte_reg2;
    reg [11:0] pending_d2;
    reg        pending_d2_valid;
    reg [6:0]  ram_ptr;

    assign shake_dout_ready = (coeff_count < 256) &&
                              ((state == GET_BYTE_0) || (state == GET_BYTE_1) || (state == GET_BYTE_2));

    wire [11:0] d1 = {byte_reg1[3:0], byte_reg0};
    wire [11:0] d2 = {byte_reg2, byte_reg1[7:4]};

    wire valid_d1 = (d1 < KYBER_Q);
    wire valid_d2 = (d2 < KYBER_Q);

    wire space_for_2 = (coeff_count <= 254);
    wire space_for_1 = (coeff_count <= 255);

    always @(posedge clk) begin
        if (!rst_n) begin
            state            <= IDLE;
            coeff_count      <= 9'd0;
            ram_we_a0        <= 1'b0;
            ram_we_a1        <= 1'b0;
            ram_addr         <= 7'd0;
            ram_ptr          <= 7'd0;
            ram_a0_din       <= 16'd0;
            ram_a1_din       <= 16'd0;
            done             <= 1'b0;
            byte_reg0        <= 8'd0;
            byte_reg1        <= 8'd0;
            byte_reg2        <= 8'd0;
            pending_d2       <= 12'd0;
            pending_d2_valid <= 1'b0;
        end else begin
            ram_we_a0 <= 1'b0;
            ram_we_a1 <= 1'b0;
            done      <= 1'b0;

            case (state)
                IDLE: begin
                    if (start) begin
                        state            <= GET_BYTE_0;
                        coeff_count      <= 9'd0;
                        ram_addr         <= 7'd0;
                        ram_ptr          <= 7'd0;
                        pending_d2       <= 12'd0;
                        pending_d2_valid <= 1'b0;
                    end
                end

                GET_BYTE_0: begin
                    if (coeff_count >= 256) begin
                        state <= IDLE;
                        done  <= 1'b1;
                    end else if (shake_dout_valid && shake_dout_ready) begin
                        byte_reg0 <= shake_dout;
                        state     <= GET_BYTE_1;
                    end
                end

                GET_BYTE_1: begin
                    if (shake_dout_valid && shake_dout_ready) begin
                        byte_reg1 <= shake_dout;
                        state     <= GET_BYTE_2;
                    end
                end

                GET_BYTE_2: begin
                    if (shake_dout_valid && shake_dout_ready) begin
                        byte_reg2 <= shake_dout;
                        state     <= PARSE_WRITE;
                    end
                end

                PARSE_WRITE: begin
                    state <= GET_BYTE_0;

                    if (valid_d1 && valid_d2 && space_for_2) begin
                        if (coeff_count[0] == 1'b0) begin
                            ram_addr    <= ram_ptr;
                            ram_we_a0   <= 1'b1;
                            ram_a0_din  <= {4'd0, d1};
                            ram_we_a1   <= 1'b1;
                            ram_a1_din  <= {4'd0, d2};
                            coeff_count <= coeff_count + 2;
                            ram_ptr     <= ram_ptr + 1;
                        end else begin
                            ram_addr         <= ram_ptr;
                            ram_we_a1        <= 1'b1;
                            ram_a1_din       <= {4'd0, d1};
                            coeff_count      <= coeff_count + 1;
                            ram_ptr          <= ram_ptr + 1;
                            pending_d2       <= d2;
                            pending_d2_valid <= 1'b1;
                            state            <= FLUSH_D2;
                        end
                    end else if (valid_d1 && space_for_1) begin
                        if (coeff_count[0] == 1'b0) begin
                            ram_addr    <= ram_ptr;
                            ram_we_a0   <= 1'b1;
                            ram_a0_din  <= {4'd0, d1};
                            coeff_count <= coeff_count + 1;
                        end else begin
                            ram_addr    <= ram_ptr;
                            ram_we_a1   <= 1'b1;
                            ram_a1_din  <= {4'd0, d1};
                            coeff_count <= coeff_count + 1;
                            ram_ptr     <= ram_ptr + 1;
                        end
                    end else if (valid_d2 && space_for_1) begin
                        if (coeff_count[0] == 1'b0) begin
                            ram_addr    <= ram_ptr;
                            ram_we_a0   <= 1'b1;
                            ram_a0_din  <= {4'd0, d2};
                            coeff_count <= coeff_count + 1;
                        end else begin
                            ram_addr    <= ram_ptr;
                            ram_we_a1   <= 1'b1;
                            ram_a1_din  <= {4'd0, d2};
                            coeff_count <= coeff_count + 1;
                            ram_ptr     <= ram_ptr + 1;
                        end
                    end
                end

                FLUSH_D2: begin
                    if (pending_d2_valid) begin
                        ram_addr         <= ram_ptr;
                        ram_we_a0        <= 1'b1;
                        ram_a0_din       <= {4'd0, pending_d2};
                        coeff_count      <= coeff_count + 1;
                        pending_d2_valid <= 1'b0;
                    end
                    state <= GET_BYTE_0;
                end

                default: state <= IDLE;
            endcase
        end
    end

endmodule
