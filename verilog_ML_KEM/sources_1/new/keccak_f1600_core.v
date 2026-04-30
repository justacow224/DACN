`timescale 1ns / 1ps

module keccak_f1600_core (
    input  wire             clk,
    input  wire             rst_n,
    // Permutation trigger
    input  wire             start,
    // Step 3.K1: load_on_start controls whether `start` reloads A from
    // state_in (legacy TB-direct mode) or keeps current A (sponge mode,
    // which builds state via byte-XOR interface below).
    input  wire             load_on_start,
    input  wire [1599:0]    state_in,
    // Step 3.K1: byte-level absorb/squeeze interface — sponge uses this
    // to XOR one input byte into A per cycle (absorb), and to read one
    // byte of A combinationally (squeeze). Eliminates the 1,600 FF
    // state_reg duplicate that sponge previously held.
    input  wire             init,             // pulse high to clear A to 0
    input  wire             xor_we,           // 1 = XOR xor_byte_data into A at xor_byte_addr
    input  wire [7:0]       xor_byte_addr,    // 0..199 byte address (lane=addr[7:3], byte_in_lane=addr[2:0])
    input  wire [7:0]       xor_byte_data,
    output wire [7:0]       byte_dout,        // combinational byte read of A at xor_byte_addr
    // Step 3.K0: state_out is now a combinational view of A (no register).
    // After the final round, A holds the post-permutation state and stays
    // stable while FSM is back in IDLE — sponge's 1-cycle-after-done capture
    // window sees identical data to the previous registered version.
    output wire [1599:0]    state_out,
    output reg              done
);

    localparam IDLE = 1'b0;
    localparam CALC = 1'b1;

    reg       fsm_state;
    reg [4:0] round_idx; 

    wire [63:0] RC [0:23];
    assign RC[0]  = 64'h0000000000000001; assign RC[1]  = 64'h0000000000008082;
    assign RC[2]  = 64'h800000000000808A; assign RC[3]  = 64'h8000000080008000;
    assign RC[4]  = 64'h000000000000808B; assign RC[5]  = 64'h0000000080000001;
    assign RC[6]  = 64'h8000000080008081; assign RC[7]  = 64'h8000000000008009;
    assign RC[8]  = 64'h000000000000008A; assign RC[9]  = 64'h0000000000000088;
    assign RC[10] = 64'h0000000080008009; assign RC[11] = 64'h000000008000000A;
    assign RC[12] = 64'h000000008000808B; assign RC[13] = 64'h800000000000008B;
    assign RC[14] = 64'h8000000000008089; assign RC[15] = 64'h8000000000008003;
    assign RC[16] = 64'h8000000000008002; assign RC[17] = 64'h8000000000000080;
    assign RC[18] = 64'h000000000000800A; assign RC[19] = 64'h800000008000000A;
    assign RC[20] = 64'h8000000080008081; assign RC[21] = 64'h8000000000008080;
    assign RC[22] = 64'h0000000080000001; assign RC[23] = 64'h8000000080008008;

    wire [63:0] current_RC = RC[round_idx];

    reg  [63:0] A [0:24];
    wire [63:0] A_next [0:24];

    wire [63:0] C [0:4];
    wire [63:0] D [0:4];
    wire [63:0] A_theta [0:24];

    genvar x, y;
    generate
        for (x = 0; x < 5; x = x + 1) begin : gen_C
            assign C[x] = A[x] ^ A[x+5] ^ A[x+10] ^ A[x+15] ^ A[x+20];
        end
        for (x = 0; x < 5; x = x + 1) begin : gen_D
            wire [63:0] c_minus_1 = C[(x+4)%5];
            wire [63:0] c_plus_1  = C[(x+1)%5];
            assign D[x] = c_minus_1 ^ {c_plus_1[62:0], c_plus_1[63:63]};
        end
        for (y = 0; y < 5; y = y + 1) begin : gen_theta_y
            for (x = 0; x < 5; x = x + 1) begin : gen_theta_x
                assign A_theta[y*5 + x] = A[y*5 + x] ^ D[x];
            end
        end
    endgenerate

    wire [63:0] B_rho_pi [0:24];
    assign B_rho_pi[0]  = A_theta[0];
    assign B_rho_pi[10] = {A_theta[1][62:0], A_theta[1][63:63]};
    assign B_rho_pi[7]  = {A_theta[10][60:0], A_theta[10][63:61]};
    assign B_rho_pi[11] = {A_theta[7][57:0], A_theta[7][63:58]};
    assign B_rho_pi[17] = {A_theta[11][53:0], A_theta[11][63:54]};
    assign B_rho_pi[18] = {A_theta[17][48:0], A_theta[17][63:49]};
    assign B_rho_pi[3]  = {A_theta[18][42:0], A_theta[18][63:43]};
    assign B_rho_pi[5]  = {A_theta[3][35:0], A_theta[3][63:36]};
    assign B_rho_pi[16] = {A_theta[5][27:0], A_theta[5][63:28]};
    assign B_rho_pi[8]  = {A_theta[16][18:0], A_theta[16][63:19]};
    assign B_rho_pi[21] = {A_theta[8][8:0], A_theta[8][63:9]};
    assign B_rho_pi[24] = {A_theta[21][61:0], A_theta[21][63:62]};
    assign B_rho_pi[4]  = {A_theta[24][49:0], A_theta[24][63:50]};
    assign B_rho_pi[15] = {A_theta[4][36:0], A_theta[4][63:37]};
    assign B_rho_pi[23] = {A_theta[15][22:0], A_theta[15][63:23]};
    assign B_rho_pi[19] = {A_theta[23][7:0], A_theta[23][63:8]};
    assign B_rho_pi[13] = {A_theta[19][55:0], A_theta[19][63:56]};
    assign B_rho_pi[12] = {A_theta[13][38:0], A_theta[13][63:39]};
    assign B_rho_pi[2]  = {A_theta[12][20:0], A_theta[12][63:21]};
    assign B_rho_pi[20] = {A_theta[2][1:0], A_theta[2][63:2]};
    assign B_rho_pi[14] = {A_theta[20][45:0], A_theta[20][63:46]};
    assign B_rho_pi[22] = {A_theta[14][24:0], A_theta[14][63:25]};
    assign B_rho_pi[9]  = {A_theta[22][2:0], A_theta[22][63:3]};
    assign B_rho_pi[6]  = {A_theta[9][43:0], A_theta[9][63:44]};
    assign B_rho_pi[1]  = {A_theta[6][19:0], A_theta[6][63:20]};

    generate
        for (y = 0; y < 5; y = y + 1) begin : gen_chi_y
            for (x = 0; x < 5; x = x + 1) begin : gen_chi_x
                wire [63:0] b_curr    = B_rho_pi[y*5 + x];
                wire [63:0] b_plus_1  = B_rho_pi[y*5 + ((x+1)%5)];
                wire [63:0] b_plus_2  = B_rho_pi[y*5 + ((x+2)%5)];
                
                wire [63:0] chi_res = b_curr ^ ((~b_plus_1) & b_plus_2);
                
                if (x == 0 && y == 0) begin
                    assign A_next[0] = chi_res ^ current_RC;
                end else begin
                    assign A_next[y*5 + x] = chi_res;
                end
            end
        end
    endgenerate

    integer i;
    always @(posedge clk) begin
        if (!rst_n) begin
            fsm_state <= IDLE;
            round_idx <= 0;
            done      <= 0;
            for (i = 0; i < 25; i = i + 1) A[i] <= 0;
        end else begin
            done <= 0;
            case (fsm_state)
                IDLE: begin
                    // Step 3.K1 priority: start > init > xor_we (mutually
                    // exclusive in practice from sponge/TB drivers, but
                    // explicit precedence avoids Vivado multi-driver warnings).
                    if (start) begin
                        fsm_state <= CALC;
                        round_idx <= 0;
                        if (load_on_start) begin
                            // Legacy TB-direct mode: load full state from state_in.
                            for (i = 0; i < 25; i = i + 1) begin
                                A[i] <= state_in[i*64 +: 64];
                            end
                        end
                        // else: sponge mode — A retains its absorb-XOR-built
                        //  contents and goes straight into permutation.
                    end else if (init) begin
                        // Sponge-issued state clear (replaces sponge's prior
                        // for-loop reset of state_reg[0:199]).
                        for (i = 0; i < 25; i = i + 1) A[i] <= 0;
                    end else if (xor_we) begin
                        // Byte-wise absorb XOR: XOR xor_byte_data into the byte
                        // of A at byte address xor_byte_addr (lane = [7:3],
                        // byte position in lane = [2:0]).
                        A[xor_byte_addr[7:3]][xor_byte_addr[2:0]*8 +: 8] <=
                            A[xor_byte_addr[7:3]][xor_byte_addr[2:0]*8 +: 8] ^ xor_byte_data;
                    end
                end

                CALC: begin
                    // Always update A from A_next (including the final round).
                    // Removes the 1,600-FF state_out copy that previously
                    // duplicated A's contents at end-of-permutation.
                    for (i = 0; i < 25; i = i + 1) begin
                        A[i] <= A_next[i];
                    end

                    if (round_idx == 23) begin
                        fsm_state <= IDLE;
                        done      <= 1;
                    end else begin
                        round_idx <= round_idx + 1;
                    end
                end
            endcase
        end
    end

    // Combinational expose of A as the 1600-bit state_out view.
    // Sponge captures one cycle after `done`, when fsm_state is IDLE and A
    // is no longer being updated, so the data is stable for the capture
    // window. No additional register is inserted, saving 1,600 FF.
    genvar gi;
    generate
        for (gi = 0; gi < 25; gi = gi + 1) begin : gen_state_out
            assign state_out[gi*64 +: 64] = A[gi];
        end
    endgenerate

    // Step 3.K1: combinational byte read for sponge squeeze path.
    // byte_dout = A[xor_byte_addr/8][xor_byte_addr%8 * 8 +: 8]
    assign byte_dout = A[xor_byte_addr[7:3]][xor_byte_addr[2:0]*8 +: 8];

endmodule