`timescale 1ns / 1ps

module poly_add_sub_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire         is_sub,  // 0 for ADD, 1 for SUB
    output reg          done,

    // Host interface for RAM access
    // host_sel: 0 for RAM A (Accumulator/Output), 1 for RAM B (Input)
    input  wire         host_sel, 
    input  wire         host_we,
    input  wire [7:0]   host_addr,
    input  wire [15:0]  host_din,
    output wire [15:0]  host_dout
);

    localparam [12:0] KYBER_Q = 13'd3329;
    
    // PIPELINE_DELAY = 2 (1 cycle RAM read + 1 cycle Math/Register)
    localparam PIPELINE_DELAY = 2; 
    
    // FSM States
    localparam IDLE  = 2'd0;
    localparam CALC  = 2'd1;
    localparam FLUSH = 2'd2; 
    
    // =================================================================
    // 1. FSM & COUNTERS
    // =================================================================
    reg [1:0] state;
    reg [7:0] step;  // 0 to 127

    wire calc_en = (state == CALC);

    always @(posedge clk) begin
        if (!rst_n) begin
            state <= IDLE;
            step  <= 0;
            done  <= 0;
        end else begin
            done <= 0;
            case (state)
                IDLE: begin
                    step <= 0;
                    if (start) state <= CALC;
                end
                
                CALC: begin
                    // 128 pairs to cover 256 coefficients
                    if (step == 127) begin
                        step  <= 0;
                        state <= FLUSH;
                    end else begin
                        step  <= step + 1;
                    end
                end
                
                FLUSH: begin
                    if (step == PIPELINE_DELAY) begin
                        state <= IDLE;
                        done  <= 1;
                    end else begin
                        step  <= step + 1;
                    end
                end
                
                default: state <= IDLE;
            endcase
        end
    end

    // =================================================================
    // 2. ADDRESS GENERATOR & BANK ROUTING
    // =================================================================
    wire [7:0] addr_even = {step[6:0], 1'b0};
    wire [6:0] ram_addr  = step[6:0];
    wire       bank_even = ^addr_even;

    // =================================================================
    // 3. PIPELINE DELAY SHIFT REGISTERS
    // =================================================================
    reg [PIPELINE_DELAY-1:0] valid_sr = 0; 
    reg [PIPELINE_DELAY-1:0] bank_even_sr;
    reg [6:0]                ram_addr_sr [0:PIPELINE_DELAY-1];

    integer i;
    always @(posedge clk) begin
        valid_sr     <= {valid_sr[PIPELINE_DELAY-2:0], calc_en};
        bank_even_sr <= {bank_even_sr[PIPELINE_DELAY-2:0], bank_even};
        
        ram_addr_sr[0] <= ram_addr;
        for (i = 1; i < PIPELINE_DELAY; i = i + 1) begin
            ram_addr_sr[i] <= ram_addr_sr[i-1];
        end
    end

    // =================================================================
    // 4. CROSSBAR (RAM READ TO MATH CORE)
    // =================================================================
    reg bank_even_d1;
    always @(posedge clk) bank_even_d1 <= bank_even;

    wire [15:0] ram_a0_dout, ram_a1_dout;
    wire [15:0] ram_b0_dout, ram_b1_dout;

    wire [15:0] a0_in = (bank_even_d1 == 1'b0) ? ram_a0_dout : ram_a1_dout;
    wire [15:0] a1_in = (bank_even_d1 == 1'b0) ? ram_a1_dout : ram_a0_dout;
    
    wire [15:0] b0_in = (bank_even_d1 == 1'b0) ? ram_b0_dout : ram_b1_dout;
    wire [15:0] b1_in = (bank_even_d1 == 1'b0) ? ram_b1_dout : ram_b0_dout;

    // =================================================================
    // 5. ADD / SUB MATH CORE (Combinational)
    // =================================================================
    // Pair 0 calculations
    wire [12:0] sum0 = a0_in[11:0] + b0_in[11:0];
    wire [15:0] res_add_0 = (sum0 >= KYBER_Q) ? {3'd0, sum0 - KYBER_Q} : {3'd0, sum0};
    wire [15:0] res_sub_0 = (a0_in[11:0] >= b0_in[11:0]) ? (a0_in - b0_in) : (a0_in + 16'd3329 - b0_in);
    wire [15:0] c0_next   = is_sub ? res_sub_0 : res_add_0;

    // Pair 1 calculations
    wire [12:0] sum1 = a1_in[11:0] + b1_in[11:0];
    wire [15:0] res_add_1 = (sum1 >= KYBER_Q) ? {3'd0, sum1 - KYBER_Q} : {3'd0, sum1};
    wire [15:0] res_sub_1 = (a1_in[11:0] >= b1_in[11:0]) ? (a1_in - b1_in) : (a1_in + 16'd3329 - b1_in);
    wire [15:0] c1_next   = is_sub ? res_sub_1 : res_add_1;

    // Pipeline Register for Math Output (Cycle 2)
    reg [15:0] c0_out, c1_out;
    always @(posedge clk) begin
        if (valid_sr[0]) begin
            c0_out <= c0_next;
            c1_out <= c1_next;
        end
    end

    // =================================================================
    // 6. WRITE DATA ROUTING (End of Pipeline)
    // =================================================================
    wire       wr_en        = valid_sr[PIPELINE_DELAY-1];
    wire       wr_bank_even = bank_even_sr[PIPELINE_DELAY-1];
    wire [6:0] wr_ram_addr  = ram_addr_sr[PIPELINE_DELAY-1];

    wire [15:0] ram_a0_din = (wr_bank_even == 1'b0) ? c0_out : c1_out;
    wire [15:0] ram_a1_din = (wr_bank_even == 1'b0) ? c1_out : c0_out;

    // =================================================================
    // 7. HOST INTERFACE & DUAL-PORT BRAM INFERENCE
    // =================================================================
    wire       host_bank     = ^host_addr;
    wire [6:0] host_ram_addr = host_addr[7:1];

    wire [6:0] sys_ram_raddr = (state == IDLE) ? host_ram_addr : ram_addr;
    wire [6:0] sys_ram_waddr = (state == IDLE) ? host_ram_addr : wr_ram_addr;
    
    wire       sys_ram_a0_we  = (state == IDLE) ? (host_we & (host_sel == 1'b0) & (host_bank == 1'b0)) : wr_en;
    wire [15:0]sys_ram_a0_din = (state == IDLE) ? host_din : ram_a0_din;
    
    wire       sys_ram_a1_we  = (state == IDLE) ? (host_we & (host_sel == 1'b0) & (host_bank == 1'b1)) : wr_en;
    wire [15:0]sys_ram_a1_din = (state == IDLE) ? host_din : ram_a1_din;

    wire       sys_ram_b0_we  = (state == IDLE) ? (host_we & (host_sel == 1'b1) & (host_bank == 1'b0)) : 1'b0;
    wire       sys_ram_b1_we  = (state == IDLE) ? (host_we & (host_sel == 1'b1) & (host_bank == 1'b1)) : 1'b0;

    reg host_bank_reg, host_sel_reg;
    always @(posedge clk) begin
        if (!rst_n) begin
            host_bank_reg <= 0;
            host_sel_reg <= 0;
        end else begin
            host_bank_reg <= host_bank;
            host_sel_reg <= host_sel;
        end
    end
    assign host_dout = (host_sel_reg == 1'b0) ? ((host_bank_reg == 1'b0) ? ram_a0_dout : ram_a1_dout) : 
                                                ((host_bank_reg == 1'b0) ? ram_b0_dout : ram_b1_dout);

    // RAM A (Accumulator / Output)
    reg [15:0] BRAM_A_0 [0:127];
    reg [15:0] BRAM_A_1 [0:127];
    reg [15:0] ram_a0_dout_reg, ram_a1_dout_reg;

    always @(posedge clk) begin
        ram_a0_dout_reg <= BRAM_A_0[sys_ram_raddr]; 
        if (sys_ram_a0_we) BRAM_A_0[sys_ram_waddr] <= sys_ram_a0_din;
    end
    assign ram_a0_dout = ram_a0_dout_reg;

    always @(posedge clk) begin
        ram_a1_dout_reg <= BRAM_A_1[sys_ram_raddr];
        if (sys_ram_a1_we) BRAM_A_1[sys_ram_waddr] <= sys_ram_a1_din;
    end
    assign ram_a1_dout = ram_a1_dout_reg;

    // RAM B (Read-Only during calculation)
    reg [15:0] BRAM_B_0 [0:127];
    reg [15:0] BRAM_B_1 [0:127];
    reg [15:0] ram_b0_dout_reg, ram_b1_dout_reg;

    always @(posedge clk) begin
        ram_b0_dout_reg <= BRAM_B_0[sys_ram_raddr]; 
        if (sys_ram_b0_we) BRAM_B_0[sys_ram_waddr] <= host_din;
    end
    assign ram_b0_dout = ram_b0_dout_reg;

    always @(posedge clk) begin
        ram_b1_dout_reg <= BRAM_B_1[sys_ram_raddr];
        if (sys_ram_b1_we) BRAM_B_1[sys_ram_waddr] <= host_din;
    end
    assign ram_b1_dout = ram_b1_dout_reg;

endmodule