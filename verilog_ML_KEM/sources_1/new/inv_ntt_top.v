`timescale 1ns / 1ps

module inv_ntt_top (
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

    localparam PIPELINE_DELAY = 6; 
    localparam [15:0] KYBER_Q = 16'd3329;
    localparam [15:0] F_INV_128 = 16'd3303; // Scaling factor

    // FSM States
    localparam IDLE  = 2'd0;
    localparam CALC  = 2'd1;
    localparam FLUSH = 2'd2; 
    
    // =================================================================
    // 1. FSM & COUNTERS
    // =================================================================
    reg [1:0] state;
    reg [2:0] stage; // Layers: 0 to 6 (Butterfly), 7 (Scaling)
    reg [7:0] step;  // 0-127 for Stage 0-6; 0-255 for Stage 7

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
                    // Stage 0-6: 128 calculations (pairs). Stage 7: 256 calculations (single elements)
                    if ((stage < 7 && step == 127) || (stage == 7 && step == 255)) begin
                        step <= 0;
                        if (stage == 3'd7) 
                            state <= FLUSH;
                        else 
                            stage <= stage + 1;
                    end else begin
                        step <= step + 1;
                    end
                end
                
                FLUSH: begin
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
    // 2. REVERSED ADDRESS GENERATOR (BIT-SPLICING)
    // =================================================================
    reg [7:0] j_a;
    reg [6:0] k_idx;

    always @(*) begin
        case(stage)
            // INVERSE NTT Address logic (Distance increases: 2, 4, 8, 16, 32, 64, 128)
            // k_idx uses bitwise NOT (~step) to perfectly map the decrementing k
            3'd0: begin j_a = {step[6:1], 1'b0, step[0]};   k_idx = {1'b1, ~step[6:1]};   end // len=2
            3'd1: begin j_a = {step[6:2], 1'b0, step[1:0]}; k_idx = {2'b01, ~step[6:2]};  end // len=4
            3'd2: begin j_a = {step[6:3], 1'b0, step[2:0]}; k_idx = {3'b001, ~step[6:3]}; end // len=8
            3'd3: begin j_a = {step[6:4], 1'b0, step[3:0]}; k_idx = {4'b0001, ~step[6:4]};end // len=16
            3'd4: begin j_a = {step[6:5], 1'b0, step[4:0]}; k_idx = {5'b00001, ~step[6:5]};end// len=32
            3'd5: begin j_a = {step[6],   1'b0, step[5:0]}; k_idx = {6'b000001, ~step[6]};end // len=64
            3'd6: begin j_a = {1'b0, step[6:0]};            k_idx = 7'b0000001;           end // len=128
            
            // STAGE 7: Scaling phase (Read sequentially from 0 to 255)
            3'd7: begin j_a = step[7:0];                    k_idx = 7'd0;                 end
            default: begin j_a = 8'd0; k_idx = 7'd0; end
        endcase
    end

    // Distance shifts based on stage. Ignored in Stage 7.
    wire [7:0] j_b = (stage == 3'd7) ? 8'd0 : (j_a | (8'h02 << stage));

    wire       bank_a = ^j_a; 
    wire [6:0] addr_a = j_a[7:1];
    wire [6:0] addr_b = j_b[7:1];

    // =================================================================
    // 3. PIPELINE DELAY SHIFT REGISTERS
    // =================================================================
    reg [PIPELINE_DELAY-1:0] valid_sr;
    reg [PIPELINE_DELAY-1:0] bank_a_sr;
    reg [2:0]                stage_sr  [0:PIPELINE_DELAY-1];
    reg [6:0]                addr_a_sr [0:PIPELINE_DELAY-1];
    reg [6:0]                addr_b_sr [0:PIPELINE_DELAY-1];

    integer i;
    always @(posedge clk) begin
        valid_sr  <= {valid_sr[PIPELINE_DELAY-2:0], calc_en};
        bank_a_sr <= {bank_a_sr[PIPELINE_DELAY-2:0], bank_a};
        
        stage_sr[0]  <= stage;
        addr_a_sr[0] <= addr_a;
        addr_b_sr[0] <= addr_b;
        
        for (i = 1; i < PIPELINE_DELAY; i = i + 1) begin
            stage_sr[i]  <= stage_sr[i-1];
            addr_a_sr[i] <= addr_a_sr[i-1];
            addr_b_sr[i] <= addr_b_sr[i-1];
        end
    end

    // =================================================================
    // 4. CROSSBAR / MUX ROUTING & RAM INTERFACE
    // =================================================================
    wire       wr_en     = valid_sr[PIPELINE_DELAY-1];
    wire       wr_bank_a = bank_a_sr[PIPELINE_DELAY-1];
    wire [2:0] wr_stage  = stage_sr[PIPELINE_DELAY-1];
    wire [6:0] wr_addr_a = addr_a_sr[PIPELINE_DELAY-1];
    wire [6:0] wr_addr_b = addr_b_sr[PIPELINE_DELAY-1];

    wire [15:0] a_prime, b_prime;

    // RAM0 Read/Write Routing 
    wire [6:0]  ram0_raddr = (bank_a == 1'b0) ? addr_a : addr_b;
    wire [6:0]  ram0_waddr = (wr_bank_a == 1'b0) ? wr_addr_a : wr_addr_b;
    
    // In Stage 7, only b_prime holds the scaled data. Route it safely.
    wire [15:0] ram0_din   = (wr_stage == 3'd7) ? b_prime : ((wr_bank_a == 1'b0) ? a_prime : b_prime);
    wire        ram0_we    = (wr_stage == 3'd7) ? (wr_en & (wr_bank_a == 1'b0)) : wr_en;
    wire [15:0] ram0_dout;

    // RAM1 Read/Write Routing
    wire [6:0]  ram1_raddr = (bank_a == 1'b0) ? addr_b : addr_a;
    wire [6:0]  ram1_waddr = (wr_bank_a == 1'b0) ? wr_addr_b : wr_addr_a;
    
    wire [15:0] ram1_din   = (wr_stage == 3'd7) ? b_prime : ((wr_bank_a == 1'b0) ? b_prime : a_prime);
    wire        ram1_we    = (wr_stage == 3'd7) ? (wr_en & (wr_bank_a == 1'b1)) : wr_en;
    wire [15:0] ram1_dout;

    // Synchronize control signals with 1-cycle RAM latency
    reg       bank_a_d1;
    reg [2:0] stage_d1;
    always @(posedge clk) begin
        bank_a_d1 <= bank_a;
        stage_d1  <= stage;
    end

    // Route RAM data to Butterfly. In Stage 7, force 'b' input to 0.
    wire [15:0] bu_in_a = (bank_a_d1 == 1'b0) ? ram0_dout : ram1_dout;
    wire [15:0] bu_in_b = (stage_d1 == 3'd7)  ? 16'd0 : ((bank_a_d1 == 1'b0) ? ram1_dout : ram0_dout);

    // =================================================================
    // 5. MODULE INSTANTIATIONS
    // =================================================================
    wire [15:0] inv_zeta_out;
    
    // Using the dedicated Inverse Twiddle ROM
    inv_zeta_rom u_inv_zeta_rom (
        .clk(clk),
        .en(calc_en),
        .addr(k_idx),
        .dout(inv_zeta_out)
    );

    // MUX to inject the 3303 scaling factor during Stage 7
    wire [15:0] twiddle_factor = (stage_d1 == 3'd7) ? F_INV_128 : inv_zeta_out;

    invntt_butterfly u_inv_butterfly (
        .clk(clk),
        .rst_n(rst_n),
        .en(1'b1),        
        .a(bu_in_a),
        .b(bu_in_b),
        .inv_zeta(twiddle_factor),
        .a_prime(a_prime),
        .b_prime(b_prime) 
    );

    // =================================================================
    // 6. HOST INTERFACE (DUAL-PORT MULTIPLEXING)
    // =================================================================
    wire       host_bank     = ^host_addr;
    wire [6:0] host_ram_addr = host_addr[7:1];

    wire [6:0] sys_ram0_raddr = (state == IDLE) ? host_ram_addr : ram0_raddr;
    wire [6:0] sys_ram1_raddr = (state == IDLE) ? host_ram_addr : ram1_raddr;

    wire [6:0] sys_ram0_waddr = (state == IDLE) ? host_ram_addr : ram0_waddr;
    wire       sys_ram0_we    = (state == IDLE) ? (host_we & (host_bank == 1'b0)) : ram0_we;
    wire [15:0]sys_ram0_din   = (state == IDLE) ? host_din : ram0_din;

    wire [6:0] sys_ram1_waddr = (state == IDLE) ? host_ram_addr : ram1_waddr;
    wire       sys_ram1_we    = (state == IDLE) ? (host_we & (host_bank == 1'b1)) : ram1_we;
    wire [15:0]sys_ram1_din   = (state == IDLE) ? host_din : ram1_din;

    assign host_dout = (host_bank == 1'b0) ? ram0_dout : ram1_dout;

    // =================================================================
    // 7. DUAL-PORT BRAM INFERENCE
    // =================================================================
    reg [15:0] BRAM_0 [0:127];
    reg [15:0] BRAM_1 [0:127];

    reg [15:0] ram0_dout_reg;
    reg [15:0] ram1_dout_reg;

    always @(posedge clk) begin
        ram0_dout_reg <= BRAM_0[sys_ram0_raddr]; 
        if (sys_ram0_we) BRAM_0[sys_ram0_waddr] <= sys_ram0_din;
    end
    assign ram0_dout = ram0_dout_reg;

    always @(posedge clk) begin
        ram1_dout_reg <= BRAM_1[sys_ram1_raddr];
        if (sys_ram1_we) BRAM_1[sys_ram1_waddr] <= sys_ram1_din;
    end
    assign ram1_dout = ram1_dout_reg;

endmodule