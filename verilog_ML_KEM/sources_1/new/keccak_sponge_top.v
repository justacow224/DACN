`timescale 1ns / 1ps

module keccak_sponge_top (
    input  wire         clk,
    input  wire         rst_n,

    // Control Interface
    input  wire         init,
    input  wire [1:0]   hash_type,
    input  wire         finalize,
    
    // Data Input
    input  wire [7:0]   din,
    input  wire         din_valid,
    output wire         din_ready,

    // Data Output
    output wire [7:0]   dout,
    output wire         dout_valid,
    input  wire         dout_ready
);

    wire [7:0] rate = (hash_type == 2'b00) ? 8'd168 :
                      (hash_type == 2'b01) ? 8'd136 :
                      (hash_type == 2'b10) ? 8'd136 : 8'd72;

    wire [7:0] domain_pad = (hash_type == 2'b00 || hash_type == 2'b01) ? 8'h1F : 8'h06;

    reg  [7:0] state_reg [0:199];
    reg  [7:0] byte_idx;
    
    wire [1599:0] core_state_in;
    wire [1599:0] core_state_out;
    reg           core_start;
    wire          core_done;

    genvar i;
    generate
        for (i = 0; i < 200; i = i + 1) begin : gen_state_mapping
            assign core_state_in[i*8 +: 8] = state_reg[i];
        end
    endgenerate

    keccak_f1600_core u_keccak_core (
        .clk(clk),
        .rst_n(rst_n),
        .start(core_start),
        .state_in(core_state_in),
        .state_out(core_state_out),
        .done(core_done)
    );

    // FSM đã được tối giản lại còn đúng 5 trạng thái cốt lõi
    localparam ST_IDLE         = 3'd0;
    localparam ST_ABSORB       = 3'd1;
    localparam ST_WAIT_ABSORB  = 3'd2;
    localparam ST_WAIT_SQUEEZE = 3'd3;
    localparam ST_SQUEEZE      = 3'd4;

    reg [2:0] state;
    integer j;

    assign din_ready  = (state == ST_ABSORB) && !finalize;
    assign dout_valid = (state == ST_SQUEEZE);
    assign dout       = state_reg[byte_idx];

    always @(posedge clk) begin
        if (!rst_n) begin
            state      <= ST_IDLE;
            byte_idx   <= 0;
            core_start <= 0;
            for (j = 0; j < 200; j = j + 1) state_reg[j] <= 8'd0;
        end 
        else if (init) begin
            state      <= ST_ABSORB;
            byte_idx   <= 0;
            core_start <= 0;
            for (j = 0; j < 200; j = j + 1) state_reg[j] <= 8'd0;
        end 
        else begin
            case (state)
                ST_IDLE: begin
                    // Wait for init
                end
                
                ST_ABSORB: begin
                    if (finalize) begin
                        // Padding song song trong 1 chu kỳ duy nhất
                        if (byte_idx == rate - 1) begin
                            state_reg[byte_idx] <= state_reg[byte_idx] ^ domain_pad ^ 8'h80;
                        end else begin
                            state_reg[byte_idx] <= state_reg[byte_idx] ^ domain_pad;
                            state_reg[rate - 1] <= state_reg[rate - 1] ^ 8'h80;
                        end
                        core_start <= 1;
                        state      <= ST_WAIT_SQUEEZE;
                    end 
                    else if (din_valid && din_ready) begin
                        state_reg[byte_idx] <= state_reg[byte_idx] ^ din;
                        if (byte_idx == rate - 1) begin
                            byte_idx   <= 0;
                            core_start <= 1;
                            state      <= ST_WAIT_ABSORB;
                        end else begin
                            byte_idx   <= byte_idx + 1;
                        end
                    end
                end
                
                ST_WAIT_ABSORB: begin
                    core_start <= 0; 
                    if (core_done) begin
                        for (j = 0; j < 200; j = j + 1) state_reg[j] <= core_state_out[j*8 +: 8];
                        state <= ST_ABSORB;
                    end
                end
                
                ST_WAIT_SQUEEZE: begin
                    core_start <= 0; 
                    if (core_done) begin
                        for (j = 0; j < 200; j = j + 1) state_reg[j] <= core_state_out[j*8 +: 8];
                        byte_idx <= 0;
                        state    <= ST_SQUEEZE;
                    end
                end
                
                ST_SQUEEZE: begin
                    if (dout_valid && dout_ready) begin
                        if (byte_idx == rate - 1) begin
                            byte_idx   <= 0;
                            core_start <= 1;
                            state      <= ST_WAIT_SQUEEZE;
                        end else begin
                            byte_idx   <= byte_idx + 1;
                        end
                    end
                end
                
                default: state <= ST_IDLE;
            endcase
        end
    end

endmodule