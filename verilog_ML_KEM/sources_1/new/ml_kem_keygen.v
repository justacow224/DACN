`timescale 1ns / 1ps

module ml_kem_keygen (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    output reg          done,

    // Random seeds input (32 bytes each)
    input  wire [255:0] seed_d_in,
    input  wire [255:0] seed_z_in,

    // Output Memory Ports 
    // pk is 1184 bytes
    output wire         pk_we,
    output wire [10:0]  pk_addr,  // 0 to 1183
    output wire [7:0]   pk_dout,

    // sk is 2400 bytes
    output wire         sk_we,
    output wire [11:0]  sk_addr,  // 0 to 2399
    output wire [7:0]   sk_dout
);

    // =================================================================
    // FSM States
    // =================================================================
    localparam S_IDLE              = 6'd0;
    localparam S_HASH_G            = 6'd1;
    localparam S_HASH_G_WAIT       = 6'd2;

    localparam S_GEN_NOISE_INIT    = 6'd3;
    localparam S_PRF_SHAKE256      = 6'd4;
    localparam S_PRF_WAIT          = 6'd5;
    localparam S_CBD               = 6'd6;
    localparam S_CBD_WAIT          = 6'd7;
    localparam S_PUMP_S_TO_NTT     = 6'd8;
    localparam S_RUN_NTT           = 6'd9;
    localparam S_PUMP_NTT_TO_S     = 6'd10;

    localparam S_MAT_MUL_INIT      = 6'd11;
    localparam S_PUMP_E_TO_ADD     = 6'd12;
    localparam S_MAT_MUL_J_INIT    = 6'd13;
    localparam S_XOF_A             = 6'd14;
    localparam S_XOF_WAIT          = 6'd15;
    localparam S_PUMP_A_TO_PW      = 6'd16;
    localparam S_PUMP_S_TO_PW      = 6'd17;
    localparam S_RUN_PW            = 6'd18;
    localparam S_PUMP_PW_TO_ADD    = 6'd19;
    localparam S_RUN_ADD           = 6'd20;
    localparam S_RUN_ADD_WAIT      = 6'd34;

    localparam S_PUMP_ADD_TO_PKBUF = 6'd21;
    localparam S_DUMP_PK           = 6'd22;
    localparam S_DUMP_PK_WAIT      = 6'd23;

    localparam S_PACK_PK           = 6'd24;
    localparam S_HASH_H_PK         = 6'd25;
    localparam S_HASH_H_WAIT       = 6'd26;

    localparam S_PACK_SK_SHAT      = 6'd27;
    localparam S_PACK_SK_SHAT_WAIT = 6'd28;
    localparam S_PACK_SK_PK        = 6'd29;
    localparam S_PACK_SK_HPK       = 6'd30;
    localparam S_PACK_SK_Z         = 6'd31;
    localparam S_DONE              = 6'd32;

    localparam S_PUMP              = 6'd33;

    reg [5:0] state;

    // =================================================================
    // Internal Registers
    // =================================================================
    reg [7:0] rho_reg [0:31];
    reg [7:0] sigma_reg [0:31];
    reg [7:0] h_pk_reg [0:31];
    
    // Keccak Buffers
    reg [63:0] prf_buf [0:15];
    reg [3:0]  prf_word_idx;
    reg [2:0]  prf_byte_idx;
    reg [63:0] prf_shift;
    
    // Loop counters
    reg [2:0] i_idx;
    reg [2:0] j_idx;
    reg [11:0] var_k;

    // Pump controller
    reg [5:0] pump_ret_state;
    reg [8:0] pump_cnt;
    reg [3:0] pump_src_sel;
    reg [3:0] pump_dst_sel;
    reg       pump_we;
    reg [7:0] pump_rd_addr;
    reg [7:0] pump_wr_addr;

    localparam SRC_S0 = 4'd0, SRC_S1 = 4'd1, SRC_S2 = 4'd2;
    localparam SRC_E0 = 4'd3, SRC_E1 = 4'd4, SRC_E2 = 4'd5;
    localparam SRC_AHAT = 4'd6, SRC_NTT = 4'd7, SRC_PW = 4'd8, SRC_ADD = 4'd9;

    localparam DST_S0 = 4'd0, DST_S1 = 4'd1, DST_S2 = 4'd2;
    localparam DST_E0 = 4'd3, DST_E1 = 4'd4, DST_E2 = 4'd5;
    localparam DST_AHAT = 4'd6, DST_NTT = 4'd7;
    localparam DST_PW_A = 4'd8, DST_PW_B = 4'd9, DST_ADD_A = 4'd10, DST_ADD_B = 4'd11;

    // Data Extraction Helpers
    wire [7:0] seed_d_byte;
    assign seed_d_byte = seed_d_in[var_k[4:0] * 8 +: 8];

    wire [7:0] seed_z_byte;
    assign seed_z_byte = seed_z_in[var_k[4:0] * 8 +: 8];

    // PK Buffer inside (for H_PK computation)
    reg [7:0] pk_buf [0:1183]; // 1184 bytes BRAM
    always @(posedge clk) begin
        if (pk_we) pk_buf[pk_addr] <= pk_dout;
    end

    // =================================================================
    // BRAM Array (7 x True Dual Port 256x16)
    // =================================================================
    reg  [7:0]  ram_addr_a [0:6];
    reg  [7:0]  ram_addr_b [0:6];
    reg  [15:0] ram_din_a [0:6];
    reg  [15:0] ram_din_b [0:6];
    reg         ram_we_a [0:6];
    reg         ram_we_b [0:6];
    wire [15:0] ram_dout_a [0:6];
    wire [15:0] ram_dout_b [0:6];

    genvar g;
    generate
        for (g = 0; g < 7; g = g + 1) begin : gen_bram
            // True Dual Port Ram (BRAM18K)
            reg [15:0] mem [0:255];
            reg [15:0] out_a, out_b;
            always @(posedge clk) begin
                if (ram_we_a[g]) mem[ram_addr_a[g]] <= ram_din_a[g];
                out_a <= mem[ram_addr_a[g]];
            end
            always @(posedge clk) begin
                if (ram_we_b[g]) mem[ram_addr_b[g]] <= ram_din_b[g];
                out_b <= mem[ram_addr_b[g]];
            end
            assign ram_dout_a[g] = out_a;
            assign ram_dout_b[g] = out_b;
        end
    endgenerate

    // =================================================================
    // Instantiate IP Cores
    // =================================================================

    // 1. Keccak Sponge
    reg         init_keccak;
    reg  [1:0]  hash_type;
    reg         finalize_keccak;
    reg  [7:0]  k_din;
    reg         k_din_valid;
    wire        k_din_ready;
    wire [7:0]  k_dout;
    wire        k_dout_valid;
    reg         fsm_k_dout_ready;
    wire        parse_k_dout_ready;

    wire k_dout_ready = (state == S_XOF_WAIT) ? parse_k_dout_ready : fsm_k_dout_ready;

    keccak_sponge_top u_keccak (
        .clk(clk), .rst_n(rst_n),
        .init(init_keccak), .hash_type(hash_type), .finalize(finalize_keccak),
        .din(k_din), .din_valid(k_din_valid), .din_ready(k_din_ready),
        .dout(k_dout), .dout_valid(k_dout_valid), .dout_ready(k_dout_ready)
    );

    // 2. Poly CBD Eta2
    reg         cbd_start;
    wire        cbd_done;
    wire [3:0]  cbd_buf_addr;
    wire [63:0] cbd_buf_dout = prf_buf[cbd_buf_addr]; // Feed from internal PRF buffer
    wire        cbd_ram_we;
    wire [6:0]  cbd_ram_addr;
    wire [15:0] cbd_ram_a0_din;
    wire [15:0] cbd_ram_a1_din;

    poly_cbd_eta2_top u_cbd (
        .clk(clk), .rst_n(rst_n), .start(cbd_start), .done(cbd_done),
        .buf_addr(cbd_buf_addr), .buf_dout(cbd_buf_dout),
        .ram_we(cbd_ram_we), .ram_addr(cbd_ram_addr), 
        .ram_a0_din(cbd_ram_a0_din), .ram_a1_din(cbd_ram_a1_din)
    );

    // 3. NTT Top
    reg         ntt_start;
    wire        ntt_done;
    wire        ntt_host_we;
    wire [7:0]  ntt_host_addr;
    wire [15:0] ntt_host_din;
    wire [15:0] ntt_host_dout;

    ntt_top u_ntt (
        .clk(clk), .rst_n(rst_n), .start(ntt_start), .done(ntt_done),
        .host_we(ntt_host_we), .host_addr(ntt_host_addr), 
        .host_din(ntt_host_din), .host_dout(ntt_host_dout)
    );

    // 4. Poly Parse Inline Top
    reg         parse_start;
    wire        parse_done;
    wire        parse_ram_we_a0;
    wire        parse_ram_we_a1;
    wire [6:0]  parse_ram_addr;
    wire [15:0] parse_ram_a0_din;
    wire [15:0] parse_ram_a1_din;

//    wire        parse_k_dout_ready;

    poly_parse_inline_top u_parse (
        .clk(clk), .rst_n(rst_n), .start(parse_start), .done(parse_done),
        .shake_dout(k_dout), .shake_dout_valid(k_dout_valid), .shake_dout_ready(parse_k_dout_ready),
        .ram_we_a0(parse_ram_we_a0), .ram_we_a1(parse_ram_we_a1),
        .ram_addr(parse_ram_addr), 
        .ram_a0_din(parse_ram_a0_din), .ram_a1_din(parse_ram_a1_din)
    );

    // 5. Poly Pointwise Top
    reg         pw_start;
    wire        pw_done;
    wire        pw_host_sel;
    wire        pw_host_we;
    wire [7:0]  pw_host_addr;
    wire [15:0] pw_host_din;
    wire [15:0] pw_host_dout;

    poly_pointwise_top u_pw (
        .clk(clk), .rst_n(rst_n), .start(pw_start), .done(pw_done),
        .host_sel(pw_host_sel), .host_we(pw_host_we), .host_addr(pw_host_addr),
        .host_din(pw_host_din), .host_dout(pw_host_dout)
    );

    // 6. Poly Add/Sub Top
    reg         add_start;
    reg         add_is_sub;
    wire        add_done;
    wire        add_host_sel;
    wire        add_host_we;
    wire [7:0]  add_host_addr;
    wire [15:0] add_host_din;
    wire [15:0] add_host_dout;

    poly_add_sub_top u_add (
        .clk(clk), .rst_n(rst_n), .start(add_start), .is_sub(add_is_sub), .done(add_done),
        .host_sel(add_host_sel), .host_we(add_host_we), .host_addr(add_host_addr),
        .host_din(add_host_din), .host_dout(add_host_dout)
    );

    // 7. Poly ToBytes
    reg         tb_start;
    wire        tb_done;
    wire [6:0]  tb_coeff_addr;
    wire [15:0] tb_coeff_a0;
    wire [15:0] tb_coeff_a1;
    wire        tb_byte_we;
    wire [8:0]  tb_byte_addr; // 0 to 383
    wire [7:0]  tb_byte_dout;

    poly_tobytes u_tb (
        .clk(clk), .rst_n(rst_n), .start(tb_start), .done(tb_done),
        .coeff_addr(tb_coeff_addr), .coeff_a0(tb_coeff_a0), .coeff_a1(tb_coeff_a1),
        .byte_we(tb_byte_we), .byte_addr(tb_byte_addr), .byte_dout(tb_byte_dout)
    );

    // =================================================================
    // Signal Routing & Pump Memory Interface
    // =================================================================

    wire [15:0] pump_read_data = 
        (pump_src_sel == SRC_S0) ? ram_dout_a[0] :
        (pump_src_sel == SRC_S1) ? ram_dout_a[1] :
        (pump_src_sel == SRC_S2) ? ram_dout_a[2] :
        (pump_src_sel == SRC_E0) ? ram_dout_a[3] :
        (pump_src_sel == SRC_E1) ? ram_dout_a[4] :
        (pump_src_sel == SRC_E2) ? ram_dout_a[5] :
        (pump_src_sel == SRC_AHAT) ? ram_dout_a[6] :
        (pump_src_sel == SRC_NTT) ? ntt_host_dout :
        (pump_src_sel == SRC_PW)  ? pw_host_dout :
        (pump_src_sel == SRC_ADD) ? add_host_dout : 16'd0;

    assign ntt_host_we = (state == S_PUMP && pump_dst_sel == DST_NTT && pump_we);
    assign ntt_host_addr = (state == S_PUMP && pump_src_sel == SRC_NTT) ? pump_rd_addr : pump_wr_addr;
    assign ntt_host_din = pump_read_data;

    assign pw_host_sel = (state == S_PUMP && pump_dst_sel == DST_PW_B) ? 1'b1 : 1'b0;
    assign pw_host_we = (state == S_PUMP && (pump_dst_sel == DST_PW_A || pump_dst_sel == DST_PW_B) && pump_we);
    assign pw_host_addr = (state == S_PUMP && pump_src_sel == SRC_PW)  ? pump_rd_addr : pump_wr_addr;
    assign pw_host_din = pump_read_data;

    assign add_host_sel = (state == S_PUMP && pump_dst_sel == DST_ADD_B) ? 1'b1 : 1'b0;
    assign add_host_we = (state == S_PUMP && (pump_dst_sel == DST_ADD_A || pump_dst_sel == DST_ADD_B) && pump_we);
    assign add_host_addr = (state == S_PUMP && pump_src_sel == SRC_ADD) ? pump_rd_addr : pump_wr_addr;
    assign add_host_din = pump_read_data;

    integer idx;
    always @(*) begin
        for (idx=0; idx<7; idx=idx+1) begin
            ram_addr_a[idx] = 8'd0;
            ram_addr_b[idx] = 8'd0;
            ram_din_a[idx]  = 16'd0;
            ram_din_b[idx]  = 16'd0;
            ram_we_a[idx]   = 1'b0;
            ram_we_b[idx]   = 1'b0;
        end
        
        // Pump logic override
        if (state == S_PUMP) begin
            // Destination (Write)
            if (pump_dst_sel < 7) begin
                ram_addr_a[pump_dst_sel] = pump_wr_addr;
                ram_din_a[pump_dst_sel]  = pump_read_data;
                ram_we_a[pump_dst_sel]   = pump_we;
            end
            // Source (Read)
            if (pump_src_sel < 7) begin
                ram_addr_a[pump_src_sel] = pump_rd_addr;
            end
        end
        
        // CBD write override
        else if (state == S_CBD || state == S_CBD_WAIT) begin
            if (i_idx < 3) begin
                ram_addr_a[i_idx] = {cbd_ram_addr, 1'b0};
                ram_addr_b[i_idx] = {cbd_ram_addr, 1'b1};
                ram_din_a[i_idx]  = cbd_ram_a0_din;
                ram_din_b[i_idx]  = cbd_ram_a1_din;
                ram_we_a[i_idx]   = cbd_ram_we;
                ram_we_b[i_idx]   = cbd_ram_we;
            end else begin
                ram_addr_a[i_idx] = {cbd_ram_addr, 1'b0};
                ram_addr_b[i_idx] = {cbd_ram_addr, 1'b1};
                ram_din_a[i_idx]  = cbd_ram_a0_din;
                ram_din_b[i_idx]  = cbd_ram_a1_din;
                ram_we_a[i_idx]   = cbd_ram_we;
                ram_we_b[i_idx]   = cbd_ram_we;
            end
        end
        
        // Parse inline write override (Target: 6 = A_hat_buf)
        else if (state == S_XOF_A || state == S_XOF_WAIT) begin
            ram_addr_a[6] = {parse_ram_addr, 1'b0};
            ram_addr_b[6] = {parse_ram_addr, 1'b1};
            ram_din_a[6]  = parse_ram_a0_din;
            ram_din_b[6]  = parse_ram_a1_din;
            ram_we_a[6]   = parse_ram_we_a0;
            ram_we_b[6]   = parse_ram_we_a1;
        end
        
        // ToBytes read override
        else if (state == S_DUMP_PK || state == S_DUMP_PK_WAIT) begin
            ram_addr_a[6] = {tb_coeff_addr, 1'b0};
            ram_addr_b[6] = {tb_coeff_addr, 1'b1};
        end
        else if (state == S_PACK_SK_SHAT || state == S_PACK_SK_SHAT_WAIT) begin
            ram_addr_a[i_idx] = {tb_coeff_addr, 1'b0};
            ram_addr_b[i_idx] = {tb_coeff_addr, 1'b1};
        end
    end

    assign tb_coeff_a0 = (state == S_DUMP_PK || state == S_DUMP_PK_WAIT) ? ram_dout_a[6] : ram_dout_a[i_idx];
    assign tb_coeff_a1 = (state == S_DUMP_PK || state == S_DUMP_PK_WAIT) ? ram_dout_b[6] : ram_dout_b[i_idx];

    // PK and SK Routing
    assign pk_we = (state == S_DUMP_PK_WAIT) ? tb_byte_we :
                   (state == S_PACK_PK)      ? 1'b1 : 1'b0;

    assign pk_addr = (state == S_DUMP_PK_WAIT) ? tb_byte_addr + {1'b0, i_idx, 8'd0} + {2'b0, i_idx, 7'd0} :
                     (state == S_PACK_PK)      ? 11'd1152 + var_k[10:0] : 11'd0;

    assign pk_dout = (state == S_DUMP_PK_WAIT) ? tb_byte_dout : 
                     (state == S_PACK_PK)      ? rho_reg[var_k[4:0]] : 8'd0;

    assign sk_we = (state == S_PACK_SK_SHAT_WAIT) ? tb_byte_we :
                   (state == S_PACK_SK_PK)        ? 1'b1 :
                   (state == S_PACK_SK_HPK)       ? 1'b1 :
                   (state == S_PACK_SK_Z)         ? 1'b1 : 1'b0;

    assign sk_addr = (state == S_PACK_SK_SHAT_WAIT) ? {1'b0, tb_byte_addr} + {2'b0, i_idx, 8'd0} + {3'b0, i_idx, 7'd0} :
                     (state == S_PACK_SK_PK)        ? 12'd1152 + var_k :
                     (state == S_PACK_SK_HPK)       ? 12'd2336 + var_k :
                     (state == S_PACK_SK_Z)         ? 12'd2368 + var_k : 12'd0;

    assign sk_dout = (state == S_PACK_SK_SHAT_WAIT) ? tb_byte_dout :
                     (state == S_PACK_SK_PK)        ? pk_buf[var_k[10:0]] :
                     (state == S_PACK_SK_HPK)       ? h_pk_reg[var_k[4:0]] :
                     (state == S_PACK_SK_Z)         ? seed_z_byte : 8'd0;


    // =================================================================
    // Main Control FSM
    // =================================================================
    always @(posedge clk) begin
        if (!rst_n) begin
            state           <= S_IDLE;
            done            <= 0;
            init_keccak     <= 0;
            finalize_keccak <= 0;
            hash_type       <= 0;
            k_din           <= 0;
            k_din_valid     <= 0;
            fsm_k_dout_ready    <= 0;
            
            cbd_start   <= 0;
            ntt_start   <= 0;
            parse_start <= 0;
            pw_start    <= 0;
            add_start   <= 0;
            tb_start    <= 0;
            add_is_sub  <= 0;
            
            i_idx <= 0;
            j_idx <= 0;
            var_k <= 0;
            
            pump_rd_addr <= 0;
            pump_wr_addr <= 0;
            pump_we      <= 0;
            pump_cnt     <= 0;
        end else begin
            // Default pulse signals
            init_keccak     <= 0;
            finalize_keccak <= 0;
            k_din_valid     <= 0;
            cbd_start       <= 0;
            ntt_start       <= 0;
            parse_start     <= 0;
            pw_start        <= 0;
            add_start       <= 0;
            tb_start        <= 0;

            case (state)
                S_IDLE: begin
                    done <= 0;
                    if (start) begin
                        state       <= S_HASH_G;
                        init_keccak <= 1;
                        hash_type   <= 2'b11; // SHA3-512
                        var_k       <= 0;
                    end
                end

                //Băm hạt giống d bằng SHA3-512 (Hàm $G$). Kết quả đầu ra là 64 byte, cắt đôi
                S_HASH_G: begin
                    if (k_din_ready) begin
                        k_din_valid <= 1;
                        if (var_k < 32) begin
                            k_din <= seed_d_byte;
                            var_k <= var_k + 1;
                        end else begin // var_k == 32
                            k_din <= 8'd3; // index k=3 for FIPS 203 ML-KEM-768
                            finalize_keccak <= 1;
                            var_k <= 0;
                            state <= S_HASH_G_WAIT;
                        end
                    end
                end

                //32 byte đầu làm rho (dùng cho XOF), 32 byte sau làm sigma (dùng cho PRF).
                S_HASH_G_WAIT: begin
                    fsm_k_dout_ready <= 1;
                    if (k_dout_valid) begin
                        if (var_k < 32) begin
                            rho_reg[var_k[4:0]] <= k_dout;
                        end else begin
                            sigma_reg[var_k[4:0]] <= k_dout;
                        end
                        
                        var_k <= var_k + 1;
                        if (var_k == 63) begin
                            fsm_k_dout_ready <= 0;
                            state <= S_GEN_NOISE_INIT;
                            i_idx <= 0;
                        end
                    end
                end

                // ================== Noise Generation Loop (i=0..5) ==================
                S_GEN_NOISE_INIT: begin
                    if (i_idx == 6) begin
                        state <= S_MAT_MUL_INIT;
                        i_idx <= 0;
                    end else begin
                        state       <= S_PRF_SHAKE256;
                        init_keccak <= 1;
                        hash_type   <= 2'b01; // SHAKE256
                        var_k       <= 0;
                    end
                end

                // Chạy SHAKE256 với khóa $\sigma$ và một nonce để tạo ra dòng dữ liệu giả ngẫu nhiên.
                S_PRF_SHAKE256: begin
                    if (k_din_ready) begin
                        k_din_valid <= 1;
                        if (var_k < 32) begin
                            k_din <= sigma_reg[var_k[4:0]];
                            var_k <= var_k + 1;
                        end else begin
                            k_din <= {5'd0, i_idx};
                            finalize_keccak <= 1;
                            var_k <= 0;
                            
                            prf_word_idx <= 0;
                            prf_byte_idx <= 0;
                            state <= S_PRF_WAIT;
                        end
                    end
                end

                S_PRF_WAIT: begin
                    fsm_k_dout_ready <= 1;
                    if (k_dout_valid) begin
                        prf_shift <= {k_dout, prf_shift[63:8]};
                        if (prf_byte_idx == 7) begin
                            prf_buf[prf_word_idx] <= {k_dout, prf_shift[63:8]};
                            prf_word_idx <= prf_word_idx + 1;
                            prf_byte_idx <= 0;
                            if (prf_word_idx == 15) begin
                                fsm_k_dout_ready <= 0;
                                state <= S_CBD;
                            end
                        end else begin
                            prf_byte_idx <= prf_byte_idx + 1;
                        end
                    end
                end

                // Đưa dòng dữ liệu từ PRF vào bộ phận lấy mẫu nhị thức trung tâm (Centered Binomial Distribution - $\eta_2$). Ghi kết quả vào BRAM con ($s_i$ và $e_i$).
                S_CBD: begin
                    cbd_start <= 1;
                    state <= S_CBD_WAIT;
                end

                S_CBD_WAIT: begin
                    if (cbd_done) begin
                        // Setup Pump: S/E -> NTT
                        state <= S_PUMP;
                        pump_src_sel <= (i_idx < 3) ? (SRC_S0 + i_idx) : (SRC_E0 + (i_idx - 3));
                        pump_dst_sel <= DST_NTT;
                        pump_ret_state <= S_RUN_NTT;
                        pump_cnt <= 0;
                        pump_we <= 0;
                    end
                end

                S_RUN_NTT: begin
                    ntt_start <= 1;
                    state <= S_PUMP_NTT_TO_S;
                end

                S_PUMP_NTT_TO_S: begin
                    if (ntt_done) begin
                        state <= S_PUMP;
                        pump_src_sel <= SRC_NTT;
                        pump_dst_sel <= (i_idx < 3) ? (DST_S0 + i_idx) : (DST_E0 + (i_idx - 3));
                        pump_ret_state <= S_GEN_NOISE_INIT; 
                        pump_cnt <= 0;
                        pump_we <= 0;

                        // Because state logic evaluated at end of pump returns to ret_state, we increment i_idx early
                        i_idx <= i_idx + 1;
                    end
                end

                // ================== Matrix Vector MultiLoop (i=0..2, j=0..2) ==================
                S_MAT_MUL_INIT: begin
                    if (i_idx == 3) begin
                        state <= S_PACK_PK;
                        var_k <= 0;
                    end else begin
                        state <= S_PUMP;
                        pump_src_sel <= SRC_E0 + i_idx;
                        pump_dst_sel <= DST_ADD_A; // Initialize accumulator with ê[i]
                        pump_ret_state <= S_MAT_MUL_J_INIT;
                        pump_cnt <= 0;
                        pump_we <= 0;
                        j_idx <= 0;
                    end
                end

                S_MAT_MUL_J_INIT: begin
                    if (j_idx == 3) begin
                        // End of row dot product, dump `add_sub.RAM_A` to A_hat_buf (acting as pk_buf)
                        state <= S_PUMP;
                        pump_src_sel <= SRC_ADD;
                        pump_dst_sel <= DST_AHAT;
                        pump_ret_state <= S_DUMP_PK;
                        pump_cnt <= 0;
                        pump_we <= 0;
                    end else begin
                        state <= S_XOF_A;
                        init_keccak <= 1;
                        hash_type   <= 2'b00; // SHAKE128
                        var_k       <= 0;
                    end
                end

                S_XOF_A: begin
                    if (k_din_ready) begin
                        k_din_valid <= 1;
                        if (var_k < 32) begin
                            k_din <= rho_reg[var_k[4:0]];
                            var_k <= var_k + 1;
                        end else if (var_k == 32) begin
                            k_din <= {5'd0, j_idx}; // j is pushed first
                            var_k <= var_k + 1;
                        end else begin
                            k_din <= {5'd0, i_idx}; // i is pushed second
                            finalize_keccak <= 1;
                            state <= S_XOF_WAIT;
                            parse_start <= 1;
                        end
                    end
                end

                S_XOF_WAIT: begin
                    // poly_parse_inline_top controls SHAKE stream directly
                    if (parse_done) begin
                        state <= S_PUMP;
                        pump_src_sel <= SRC_AHAT;
                        pump_dst_sel <= DST_PW_A; // Â[i][j] into RAM_A
                        pump_ret_state <= S_PUMP_S_TO_PW;
                        pump_cnt <= 0;
                        pump_we <= 0;
                    end
                end

                S_PUMP_S_TO_PW: begin
                    state <= S_PUMP;
                    pump_src_sel <= SRC_S0 + j_idx;
                    pump_dst_sel <= DST_PW_B; // ŝ[j] into RAM_B
                    pump_ret_state <= S_RUN_PW;
                    pump_cnt <= 0;
                    pump_we <= 0;
                end

                S_RUN_PW: begin
                    pw_start <= 1;
                    state <= S_PUMP_PW_TO_ADD;
                end

                S_PUMP_PW_TO_ADD: begin
                    if (pw_done) begin
                        state <= S_PUMP;
                        pump_src_sel <= SRC_PW;
                        pump_dst_sel <= DST_ADD_B; 
                        pump_ret_state <= S_RUN_ADD;
                        pump_cnt <= 0;
                        pump_we <= 0;
                    end
                end

                S_RUN_ADD: begin
                    add_start <= 1;
                    add_is_sub <= 0;
                    state <= S_RUN_ADD_WAIT;
                end
                
                S_RUN_ADD_WAIT: begin
                    if (add_done) begin
                        j_idx <= j_idx + 1;
                        state <= S_MAT_MUL_J_INIT;
                    end
                end

                S_DUMP_PK: begin
                    tb_start <= 1;
                    state <= S_DUMP_PK_WAIT;
                end

                S_DUMP_PK_WAIT: begin
                    if (tb_done) begin
                        i_idx <= i_idx + 1;
                        state <= S_MAT_MUL_INIT;
                    end
                end

                // ================== Pack Outputs ==================
                S_PACK_PK: begin
                    if (var_k < 32) begin
                        var_k <= var_k + 1;
                    end else begin
                        state <= S_HASH_H_PK;
                        var_k <= 0;
                        init_keccak <= 1;
                        hash_type <= 2'b10; // SHA3-256
                    end
                end

                S_HASH_H_PK: begin
                    if (k_din_ready) begin
                        k_din_valid <= 1;
                        if (var_k < 1184) begin
                            k_din <= pk_buf[var_k[10:0]];
                            var_k <= var_k + 1;
                        end else begin
                            finalize_keccak <= 1;
                            var_k <= 0;
                            state <= S_HASH_H_WAIT;
                        end
                    end
                end

                S_HASH_H_WAIT: begin
                    fsm_k_dout_ready <= 1;
                    if (k_dout_valid) begin
                        h_pk_reg[var_k[4:0]] <= k_dout;
                        var_k <= var_k + 1;
                        if (var_k == 31) begin
                            fsm_k_dout_ready <= 0;
                            state <= S_PACK_SK_SHAT;
                            i_idx <= 0;
                        end
                    end
                end

                S_PACK_SK_SHAT: begin
                    if (i_idx == 3) begin
                        state <= S_PACK_SK_PK;
                        var_k <= 0;
                    end else begin
                        tb_start <= 1;
                        state <= S_PACK_SK_SHAT_WAIT;
                    end
                end

                S_PACK_SK_SHAT_WAIT: begin
                    if (tb_done) begin
                        i_idx <= i_idx + 1;
                        state <= S_PACK_SK_SHAT;
                    end
                end

                S_PACK_SK_PK: begin
                    if (var_k < 1184) begin
                        var_k <= var_k + 1;
                    end else begin
                        state <= S_PACK_SK_HPK;
                        var_k <= 0;
                    end
                end

                S_PACK_SK_HPK: begin
                    if (var_k < 32) begin
                        var_k <= var_k + 1;
                    end else begin
                        state <= S_PACK_SK_Z;
                        var_k <= 0;
                    end
                end

                S_PACK_SK_Z: begin
                    if (var_k < 32) begin
                        var_k <= var_k + 1;
                    end else begin
                        state <= S_DONE;
                    end
                end

                // ================== Core Pump Engine (257 cycles) ==================
                S_PUMP: begin
                    if (pump_cnt == 257) begin
                        pump_we <= 0;
                        pump_cnt <= 0;
                        if (pump_dst_sel == DST_NTT) ntt_start <= 1;
                        
                        state <= pump_ret_state;
                    end else begin
                        pump_rd_addr <= pump_cnt;
                        pump_wr_addr <= pump_cnt - 1;
                        pump_we      <= (pump_cnt > 0);
                        pump_cnt     <= pump_cnt + 1;
                    end
                end

                S_DONE: begin
                    done <= 1;
                end

                default: state <= S_IDLE;
            endcase
        end
    end
endmodule