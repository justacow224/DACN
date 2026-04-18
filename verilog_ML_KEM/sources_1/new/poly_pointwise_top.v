`timescale 1ns / 1ps

module poly_pointwise_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    output reg          done,

    // Host interface for RAM access
    // host_sel: 0 for RAM A (Output), 1 for RAM B (Input only)
    input  wire         host_sel, 
    input  wire         host_we,
    input  wire [7:0]   host_addr,
    input  wire [15:0]  host_din,
    output wire [15:0]  host_dout
);

    // CORRECT DELAY: 1 cycle (RAM Read) + 9 cycles (BaseMul) = 10 cycles
    localparam PIPELINE_DELAY = 10; 
    
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
                    // 128 base multiplications for 256 coefficients
                    if (step == 127) begin
                        step  <= 0;
                        state <= FLUSH;
                    end else begin
                        step  <= step + 1;
                    end
                end
                
                FLUSH: begin
                    // REVERTED: Flush exactly equal to pipeline delay
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
    // Pipeline validity/address tracking for delayed writeback
    reg [PIPELINE_DELAY-1:0] valid_sr = 0; 
    reg [PIPELINE_DELAY-1:0] bank_even_sr;
    reg [6:0]                ram_addr_sr [0:PIPELINE_DELAY-1];

    integer i;
    always @(posedge clk) begin
        if (!rst_n) begin
            valid_sr     <= {PIPELINE_DELAY{1'b0}};
            bank_even_sr <= {PIPELINE_DELAY{1'b0}};
            for (i = 0; i < PIPELINE_DELAY; i = i + 1) begin
                ram_addr_sr[i] <= 7'd0;
            end
        end else begin
            valid_sr     <= {valid_sr[PIPELINE_DELAY-2:0], calc_en};
            bank_even_sr <= {bank_even_sr[PIPELINE_DELAY-2:0], bank_even};

            ram_addr_sr[0] <= ram_addr;
            for (i = 1; i < PIPELINE_DELAY; i = i + 1) begin
                ram_addr_sr[i] <= ram_addr_sr[i-1];
            end
        end
    end

    // =================================================================
    // 4. MODULE INSTANTIATIONS
    // =================================================================
    wire [15:0] gamma_out;
    poly_gamma_rom u_gamma_rom (
        .clk(clk),
        .en(1'b1),
        .addr(step[6:0]),
        .dout(gamma_out)
    );

    wire [15:0] a0_in, a1_in, b0_in, b1_in;
    wire [15:0] c0_out, c1_out;

    poly_basemul u_basemul (
        .clk(clk),
        .rst_n(rst_n),
        .en(1'b1),        
        .a0(a0_in),
        .a1(a1_in),
        .b0(b0_in),
        .b1(b1_in),
        .gamma(gamma_out),
        .c0_out(c0_out),
        .c1_out(c1_out)
    );

    // =================================================================
    // 5. CROSSBAR / MUX ROUTING & RAM INTERFACE
    // =================================================================
    reg bank_even_d1;
    always @(posedge clk) begin
        if (!rst_n) bank_even_d1 <= 1'b0;
        else        bank_even_d1 <= bank_even;
    end

    wire [15:0] ram_a0_dout, ram_a1_dout;
    wire [15:0] ram_b0_dout, ram_b1_dout;

    assign a0_in = (bank_even_d1 == 1'b0) ? ram_a0_dout : ram_a1_dout;
    assign a1_in = (bank_even_d1 == 1'b0) ? ram_a1_dout : ram_a0_dout;
    
    assign b0_in = (bank_even_d1 == 1'b0) ? ram_b0_dout : ram_b1_dout;
    assign b1_in = (bank_even_d1 == 1'b0) ? ram_b1_dout : ram_b0_dout;

    wire       wr_en        = valid_sr[PIPELINE_DELAY-1];
    wire       wr_bank_even = bank_even_sr[PIPELINE_DELAY-1];
    wire [6:0] wr_ram_addr  = ram_addr_sr[PIPELINE_DELAY-1];

    wire [15:0] ram_a0_din = (wr_bank_even == 1'b0) ? c0_out : c1_out;
    wire [15:0] ram_a1_din = (wr_bank_even == 1'b0) ? c1_out : c0_out;

    // =================================================================
    // 6. HOST INTERFACE & DUAL-PORT BRAM INFERENCE
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
    bram_sdp_128x16 u_ram_a0 (
        .clk(clk),
        .rst_n(rst_n),
        .raddr(sys_ram_raddr),
        .waddr(sys_ram_waddr),
        .we(sys_ram_a0_we),
        .din(sys_ram_a0_din),
        .dout(ram_a0_dout)
    );

    bram_sdp_128x16 u_ram_a1 (
        .clk(clk),
        .rst_n(rst_n),
        .raddr(sys_ram_raddr),
        .waddr(sys_ram_waddr),
        .we(sys_ram_a1_we),
        .din(sys_ram_a1_din),
        .dout(ram_a1_dout)
    );

    // RAM B (Read-Only during calculation)
    bram_sdp_128x16 u_ram_b0 (
        .clk(clk),
        .rst_n(rst_n),
        .raddr(sys_ram_raddr),
        .waddr(sys_ram_waddr),
        .we(sys_ram_b0_we),
        .din(host_din),
        .dout(ram_b0_dout)
    );

    bram_sdp_128x16 u_ram_b1 (
        .clk(clk),
        .rst_n(rst_n),
        .raddr(sys_ram_raddr),
        .waddr(sys_ram_waddr),
        .we(sys_ram_b1_we),
        .din(host_din),
        .dout(ram_b1_dout)
    );

endmodule
