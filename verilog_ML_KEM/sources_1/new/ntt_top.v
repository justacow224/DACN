`timescale 1ns / 1ps

module ntt_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    output reg          done,

    // Host interface for RAM access
    input  wire         host_we,
    input  wire [7:0]   host_addr,
    input  wire [15:0]  host_din,
    output wire [15:0]  host_dout
);

    // =================================================================
    // 0. SYSTEM PARAMETERS
    // =================================================================
    // Total latency = 1 (RAM Read) + 5 (Butterfly) = 6 cycles
    localparam PIPELINE_DELAY = 6; 

    // FSM States
    localparam IDLE  = 2'd0;
    localparam CALC  = 2'd1;
    localparam FLUSH = 2'd2; 
    
    // =================================================================
    // 1. FSM & COUNTERS
    // =================================================================
    reg [1:0] state;
    reg [2:0] stage; // Layers: 0 to 6
    reg [6:0] step;  // 128 calculations per layer

    wire calc_en = (state == CALC);

    always @(posedge clk) begin
        if (!rst_n) begin
            state <= IDLE;
            stage <= 0;
            step  <= 0;
            done  <= 0;
        end else begin
            done <= 0;
            case (state)
                IDLE: begin
                    stage <= 0;
                    step  <= 0;
                    if (start) state <= CALC;
                end
                
                CALC: begin
                    if (step == 127) begin
                        step <= 0;
                        if (stage == 3'd6) 
                            state <= FLUSH;
                        else 
                            stage <= stage + 1;
                    end else begin
                        step <= step + 1;
                    end
                end
                
                FLUSH: begin
                    // Wait for the last data to propagate through the pipeline
                    if (step == PIPELINE_DELAY) begin
                        state <= IDLE;
                        done  <= 1;
                    end else begin
                        step <= step + 1;
                    end
                end
                
                default: state <= IDLE;
            endcase
        end
    end

    // =================================================================
    // 2. ADDRESS GENERATOR (BIT-SPLICING)
    // =================================================================
    reg [7:0] j_a;
    reg [6:0] k_idx;

    // Static address generation based on current stage and step
    always @(*) begin
        case(stage)
            3'd0: begin j_a = {1'b0, step[6:0]};            k_idx = 7'd1; end
            3'd1: begin j_a = {step[6],   1'b0, step[5:0]}; k_idx = {5'd0, 1'b1, step[6]}; end
            3'd2: begin j_a = {step[6:5], 1'b0, step[4:0]}; k_idx = {4'd0, 1'b1, step[6:5]}; end
            3'd3: begin j_a = {step[6:4], 1'b0, step[3:0]}; k_idx = {3'd0, 1'b1, step[6:4]}; end
            3'd4: begin j_a = {step[6:3], 1'b0, step[2:0]}; k_idx = {2'd0, 1'b1, step[6:3]}; end
            3'd5: begin j_a = {step[6:2], 1'b0, step[1:0]}; k_idx = {1'd0, 1'b1, step[6:2]}; end
            3'd6: begin j_a = {step[6:1], 1'b0, step[0]};   k_idx = {      1'b1, step[6:1]}; end
            default: begin j_a = 8'd0; k_idx = 7'd0; end
        endcase
    end

    // Address B is simply Address A with the distance bit flipped
    wire [7:0] j_b = j_a | (8'h01 << (7 - stage));

    // Conflict-free memory banking using XOR
    wire       bank_a = ^j_a; 
    wire [6:0] addr_a = j_a[7:1];
    wire [6:0] addr_b = j_b[7:1];

    // =================================================================
    // 3. PIPELINE DELAY SHIFT REGISTERS
    // =================================================================
    reg [PIPELINE_DELAY-1:0] valid_sr;
    reg [PIPELINE_DELAY-1:0] bank_a_sr;
    reg [6:0] addr_a_sr [0:PIPELINE_DELAY-1];
    reg [6:0] addr_b_sr [0:PIPELINE_DELAY-1];

    integer i;
    always @(posedge clk) begin
        valid_sr  <= {valid_sr[PIPELINE_DELAY-2:0], calc_en};
        bank_a_sr <= {bank_a_sr[PIPELINE_DELAY-2:0], bank_a};
        
        addr_a_sr[0] <= addr_a;
        addr_b_sr[0] <= addr_b;
        for (i = 1; i < PIPELINE_DELAY; i = i + 1) begin
            addr_a_sr[i] <= addr_a_sr[i-1];
            addr_b_sr[i] <= addr_b_sr[i-1];
        end
    end

    // =================================================================
    // 4. CROSSBAR / MUX ROUTING
    // =================================================================
    // Write signals (extracted from the end of the shift register)
    wire       wr_en     = valid_sr[PIPELINE_DELAY-1];
    wire       wr_bank_a = bank_a_sr[PIPELINE_DELAY-1];
    wire [6:0] wr_addr_a = addr_a_sr[PIPELINE_DELAY-1];
    wire [6:0] wr_addr_b = addr_b_sr[PIPELINE_DELAY-1];

    wire [15:0] a_prime, b_prime;

    // RAM Read/Write Routing Logic
    wire [6:0]  ram0_raddr = (bank_a == 1'b0) ? addr_a : addr_b;
    wire [6:0]  ram0_waddr = (wr_bank_a == 1'b0) ? wr_addr_a : wr_addr_b;
    wire [15:0] ram0_din   = (wr_bank_a == 1'b0) ? a_prime : b_prime;
    wire        ram0_we    = wr_en;
    wire [15:0] ram0_dout;

    wire [6:0]  ram1_raddr = (bank_a == 1'b0) ? addr_b : addr_a;
    wire [6:0]  ram1_waddr = (wr_bank_a == 1'b0) ? wr_addr_b : wr_addr_a;
    wire [15:0] ram1_din   = (wr_bank_a == 1'b0) ? b_prime : a_prime;
    wire        ram1_we    = wr_en;
    wire [15:0] ram1_dout;

    // Delay bank_a by 1 cycle to synchronize with RAM read latency
    reg bank_a_d1;
    always @(posedge clk) bank_a_d1 <= bank_a;

    wire [15:0] bu_in_a = (bank_a_d1 == 1'b0) ? ram0_dout : ram1_dout;
    wire [15:0] bu_in_b = (bank_a_d1 == 1'b0) ? ram1_dout : ram0_dout;

    // =================================================================
    // 5. MODULE INSTANTIATIONS
    // =================================================================
    wire [15:0] zeta_out;
    zeta_rom u_zeta_rom (
        .clk(clk),
        .en(calc_en),
        .addr(k_idx),
        .dout(zeta_out)
    );

    ntt_butterfly u_butterfly (
        .clk(clk),
        .rst_n(rst_n),
        .en(1'b1),        // Always enabled, garbage is masked by write_enable
        .a(bu_in_a),
        .b(bu_in_b),
        .zeta(zeta_out),
        .a_prime(a_prime),
        .b_prime(b_prime)
    );

    // =================================================================
    // 6. HOST INTERFACE (DUAL-PORT MULTIPLEXING)
    // =================================================================
    wire       host_bank     = ^host_addr;
    wire [6:0] host_ram_addr = host_addr[7:1];

    // Read Port Multiplexing
    wire [6:0] sys_ram0_raddr = (state == IDLE) ? host_ram_addr : ram0_raddr;
    wire [6:0] sys_ram1_raddr = (state == IDLE) ? host_ram_addr : ram1_raddr;

    // Write Port Multiplexing
    wire [6:0] sys_ram0_waddr = (state == IDLE) ? host_ram_addr : ram0_waddr;
    wire       sys_ram0_we    = (state == IDLE) ? (host_we & (host_bank == 1'b0)) : ram0_we;
    wire [15:0]sys_ram0_din   = (state == IDLE) ? host_din : ram0_din;

    wire [6:0] sys_ram1_waddr = (state == IDLE) ? host_ram_addr : ram1_waddr;
    wire       sys_ram1_we    = (state == IDLE) ? (host_we & (host_bank == 1'b1)) : ram1_we;
    wire [15:0]sys_ram1_din   = (state == IDLE) ? host_din : ram1_din;

    reg host_bank_reg;
    always @(posedge clk) begin
        if (!rst_n) host_bank_reg <= 0;
        else host_bank_reg <= host_bank;
    end
    assign host_dout = (host_bank_reg == 1'b0) ? ram0_dout : ram1_dout;

    // =================================================================
    // 7. DUAL-PORT BRAM INFERENCE
    // =================================================================
    reg [15:0] BRAM_0 [0:127];
    reg [15:0] BRAM_1 [0:127];

    reg [15:0] ram0_dout_reg;
    reg [15:0] ram1_dout_reg;

    // Bank 0
    always @(posedge clk) begin
        ram0_dout_reg <= BRAM_0[sys_ram0_raddr]; 
        if (sys_ram0_we) begin
            BRAM_0[sys_ram0_waddr] <= sys_ram0_din;
        end
    end
    assign ram0_dout = ram0_dout_reg;

    // Bank 1
    always @(posedge clk) begin
        ram1_dout_reg <= BRAM_1[sys_ram1_raddr];
        if (sys_ram1_we) begin
            BRAM_1[sys_ram1_waddr] <= sys_ram1_din;
        end
    end
    assign ram1_dout = ram1_dout_reg;

endmodule