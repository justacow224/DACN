`timescale 1ns / 1ps

module ml_kem_decaps #(
    parameter HAS_INTERNAL_KECCAK  = 1,
    parameter HAS_INTERNAL_ENCRYPT = 1,
    parameter HAS_INTERNAL_POLY    = 1
) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    output reg          busy,
    output reg          done,

    // Input preload
    // in_sel = 0: dk (2400 bytes)
    // in_sel = 1: ct (1088 bytes)
    input  wire         in_we,
    input  wire         in_sel,
    input  wire [11:0]  in_addr,
    input  wire [7:0]   in_wdata,

    // Output readback (shared secret)
    input  wire         out_rd,
    input  wire [10:0]  out_addr,
    output reg  [7:0]   out_rdata,
    output reg          out_valid,

    // Packed shared secret output
    output reg  [255:0] ss_out,

    // External keccak interface, used only when HAS_INTERNAL_KECCAK == 0.
    output wire         ext_k_init,
    output wire [1:0]   ext_k_hash_type,
    output wire         ext_k_finalize,
    output wire [7:0]   ext_k_din,
    output wire         ext_k_din_valid,
    input  wire         ext_k_din_ready,
    input  wire [7:0]   ext_k_dout,
    input  wire         ext_k_dout_valid,
    output wire         ext_k_dout_ready,

    // External kpke_encrypt interface (used only when HAS_INTERNAL_ENCRYPT==0).
    // Forward signals: drive shared kpke_encrypt instance hosted at parent.
    output wire         ext_enc_start,
    output wire         ext_enc_in_we,
    output wire [1:0]   ext_enc_in_sel,
    output wire [10:0]  ext_enc_in_addr,
    output wire [7:0]   ext_enc_in_wdata,
    // Backward signals: shared kpke_encrypt status returned from parent.
    input  wire         ext_enc_busy,
    input  wire         ext_enc_done,
    input  wire         ext_enc_ct_we,
    input  wire [10:0]  ext_enc_ct_addr,
    input  wire [7:0]   ext_enc_ct_dout,

    // External shared decrypt-side poly-engine interface, used only when
    // HAS_INTERNAL_POLY == 0.
    output wire         ext_dec_fromb_start,
    input  wire         ext_dec_fromb_done,
    input  wire [8:0]   ext_dec_fromb_byte_addr,
    output wire [7:0]   ext_dec_fromb_byte_din,
    input  wire         ext_dec_fromb_coeff_we,
    input  wire [6:0]   ext_dec_fromb_coeff_addr,
    input  wire [15:0]  ext_dec_fromb_coeff_a0,
    input  wire [15:0]  ext_dec_fromb_coeff_a1,

    output wire         ext_dec_ntt_start,
    input  wire         ext_dec_ntt_done,
    output wire         ext_dec_ntt_host_we,
    output wire [7:0]   ext_dec_ntt_host_addr,
    output wire [15:0]  ext_dec_ntt_host_din,
    input  wire [15:0]  ext_dec_ntt_host_dout,

    output wire         ext_dec_intt_start,
    input  wire         ext_dec_intt_done,
    output wire         ext_dec_intt_host_we,
    output wire [7:0]   ext_dec_intt_host_addr,
    output wire [15:0]  ext_dec_intt_host_din,
    input  wire [15:0]  ext_dec_intt_host_dout,

    output wire         ext_dec_pw_start,
    input  wire         ext_dec_pw_done,
    output wire         ext_dec_pw_host_sel,
    output wire         ext_dec_pw_host_we,
    output wire [7:0]   ext_dec_pw_host_addr,
    output wire [15:0]  ext_dec_pw_host_din,
    input  wire [15:0]  ext_dec_pw_host_dout,

    output wire         ext_dec_add_start,
    output wire         ext_dec_add_is_sub,
    input  wire         ext_dec_add_done,
    output wire         ext_dec_add_host_sel,
    output wire         ext_dec_add_host_we,
    output wire [7:0]   ext_dec_add_host_addr,
    output wire [15:0]  ext_dec_add_host_din,
    input  wire [15:0]  ext_dec_add_host_dout,

    output wire         ext_dec_comp_start,
    output wire [1:0]   ext_dec_comp_d_sel,
    input  wire         ext_dec_comp_done,
    input  wire [6:0]   ext_dec_comp_coeff_addr,
    output wire [15:0]  ext_dec_comp_coeff_a0,
    output wire [15:0]  ext_dec_comp_coeff_a1,
    input  wire         ext_dec_comp_byte_we,
    input  wire [8:0]   ext_dec_comp_byte_addr,
    input  wire [7:0]   ext_dec_comp_byte_dout
);

    localparam [4:0] S_IDLE          = 5'd0;
    localparam [4:0] S_DEC_PRELOAD   = 5'd1;
    localparam [4:0] S_DEC_START     = 5'd2;
    localparam [4:0] S_DEC_WAIT      = 5'd3;
    localparam [4:0] S_CAPTURE_M     = 5'd4;
    localparam [4:0] S_HASH_G_INIT   = 5'd5;
    localparam [4:0] S_HASH_G_ABS    = 5'd6;
    localparam [4:0] S_HASH_G_FIN    = 5'd7;
    localparam [4:0] S_HASH_G_WAIT   = 5'd8;
    localparam [4:0] S_HASH_J_INIT   = 5'd9;
    localparam [4:0] S_HASH_J_ABS    = 5'd10;
    localparam [4:0] S_HASH_J_FIN    = 5'd11;
    localparam [4:0] S_HASH_J_WAIT   = 5'd12;
    localparam [4:0] S_ENC_PRELOAD   = 5'd13;
    localparam [4:0] S_ENC_START     = 5'd14;
    localparam [4:0] S_ENC_WAIT      = 5'd15;
    localparam [4:0] S_ENC_SETTLE    = 5'd16;
    localparam [4:0] S_COMPARE_INIT  = 5'd17;
    localparam [4:0] S_COMPARE       = 5'd18;
    localparam [4:0] S_OUTPUT        = 5'd19;
    localparam [4:0] S_ZEROIZE       = 5'd20;
    localparam [4:0] S_DONE          = 5'd21;
    localparam [4:0] S_DEC_PRELOAD_REQ = 5'd22;
    localparam [4:0] S_DEC_PRELOAD_SEND = 5'd23;
    localparam [4:0] S_HASH_J_CT_SEND = 5'd24;
    localparam [4:0] S_ENC_PRELOAD_EK_SEND = 5'd25;
    localparam [4:0] S_COMPARE_REQ    = 5'd26;
    localparam [4:0] S_COMPARE_WAIT   = 5'd27;
    localparam [4:0] S_DEC_PRELOAD_WAIT = 5'd28;
    localparam [4:0] S_HASH_J_CT_WAIT = 5'd29;
    localparam [4:0] S_ENC_PRELOAD_EK_WAIT = 5'd30;

    reg [4:0] state;

    reg [7:0] h_reg [0:31];
    reg [7:0] z_reg [0:31];

    reg         dk_rd_en;
    reg [10:0]  dk_rd_addr;
    wire [7:0]  dk_rd_data;

    reg         ek_rd_en;
    reg [10:0]  ek_rd_addr;
    wire [7:0]  ek_rd_data;

    reg         ct_rd_en;
    reg [10:0]  ct_rd_addr;
    wire [7:0]  ct_rd_data;

    reg         ct_prime_rd_en;
    reg [10:0]  ct_prime_rd_addr;
    wire [7:0]  ct_prime_rd_data;

    reg [7:0] m_prime  [0:31];
    reg [7:0] k_prime  [0:31];
    reg [7:0] r_prime  [0:31];
    reg [7:0] k_reject [0:31];
    reg [7:0] ss_buf   [0:31];
    reg [255:0] k_prime_vec;
    reg [255:0] k_reject_vec;
    reg         enc_ct_last_seen;

    reg         init_keccak;
    reg  [1:0]  hash_type;
    reg         finalize_keccak;
    reg  [7:0]  k_din;
    reg         k_din_valid;
    wire        k_din_ready;
    wire [7:0]  k_dout;
    wire        k_dout_valid;
    reg         fsm_k_dout_ready;

    reg         core_start;
    reg  [1:0]  core_mode;
    reg         core_in_we;
    reg  [1:0]  core_in_sel;
    reg  [10:0] core_in_addr;
    reg  [7:0]  core_in_wdata;
    wire        core_done;
    wire [255:0] core_m_out;
    wire        core_ct_we;
    wire [10:0] core_ct_addr;
    wire [7:0]  core_ct_dout;
    wire        core_k_init;
    wire [1:0]  core_k_hash_type;
    wire        core_k_finalize;
    wire [7:0]  core_k_din;
    wire        core_k_din_valid;
    wire        core_k_din_ready;
    wire [7:0]  core_k_dout;
    wire        core_k_dout_valid;
    wire        core_k_dout_ready;

    // When HAS_INTERNAL_ENCRYPT == 0, kpke_core no longer hosts its own
    // u_encrypt (and u_decrypt does not use keccak), so the local encrypt-side
    // keccak source is silent. The lifted shared kpke_encrypt at the top level
    // owns keccak directly via its own ext_k_* path.
    wire        core_owns_keccak = (HAS_INTERNAL_ENCRYPT != 0) &&
                                   ((state == S_DEC_START)  ||
                                    (state == S_DEC_WAIT)   ||
                                    (state == S_ENC_START)  ||
                                    (state == S_ENC_WAIT)   ||
                                    (state == S_ENC_SETTLE));

    wire        shared_k_init       = core_owns_keccak ? core_k_init       : init_keccak;
    wire [1:0]  shared_k_hash_type  = core_owns_keccak ? core_k_hash_type  : hash_type;
    wire        shared_k_finalize   = core_owns_keccak ? core_k_finalize   : finalize_keccak;
    wire [7:0]  shared_k_din        = core_owns_keccak ? core_k_din        : k_din;
    wire        shared_k_din_valid  = core_owns_keccak ? core_k_din_valid  : k_din_valid;
    wire        shared_k_dout_ready = core_owns_keccak ? core_k_dout_ready : fsm_k_dout_ready;
    wire        shared_k_din_ready;
    wire [7:0]  shared_k_dout;
    wire        shared_k_dout_valid;

    assign k_din_ready         = core_owns_keccak ? 1'b0 : shared_k_din_ready;
    assign k_dout              = shared_k_dout;
    assign k_dout_valid        = core_owns_keccak ? 1'b0 : shared_k_dout_valid;
    assign core_k_din_ready    = core_owns_keccak ? shared_k_din_ready : 1'b0;
    assign core_k_dout         = core_owns_keccak ? shared_k_dout : 8'd0;
    assign core_k_dout_valid   = core_owns_keccak ? shared_k_dout_valid : 1'b0;

    reg [11:0] var_k;
    reg [7:0]  xor_acc;
    reg        match_reg;
    wire [7:0] match_mask = {8{match_reg}};

    wire [7:0] compare_xor_byte = ct_rd_data ^ ct_prime_rd_data;
    wire [7:0] compare_xor_next = xor_acc | compare_xor_byte;
    wire [10:0] ek_wr_addr = in_addr - 12'd1152;
    reg [10:0] dbg_cmp_idx;
    reg [7:0]  dbg_ct_byte;
    reg [7:0]  dbg_ct_prime_byte;
    reg        dbg_cmp_seen;
    reg [11:0] dbg_enc_ct_count;
    integer i;

    xpm_ram_sdp_byte #(
        .ADDR_WIDTH(11),
        .DEPTH(2048),
        .READ_LATENCY(1)
    ) u_dk_pke_buf_ram (
        .clk    (clk),
        .wr_en  (in_we && !busy && !in_sel && (in_addr < 12'd1152)),
        .wr_addr(in_addr[10:0]),
        .wr_data(in_wdata),
        .rd_en  (dk_rd_en),
        .rd_addr(dk_rd_addr),
        .rd_data(dk_rd_data)
    );

    xpm_ram_sdp_byte #(
        .ADDR_WIDTH(11),
        .DEPTH(2048),
        .READ_LATENCY(1)
    ) u_ek_buf_ram (
        .clk    (clk),
        .wr_en  (in_we && !busy && !in_sel && (in_addr >= 12'd1152) && (in_addr < 12'd2336)),
        .wr_addr(ek_wr_addr),
        .wr_data(in_wdata),
        .rd_en  (ek_rd_en),
        .rd_addr(ek_rd_addr),
        .rd_data(ek_rd_data)
    );

    xpm_ram_sdp_byte #(
        .ADDR_WIDTH(11),
        .DEPTH(2048),
        .READ_LATENCY(1)
    ) u_ct_buf_ram (
        .clk    (clk),
        .wr_en  (in_we && !busy && in_sel && (in_addr < 12'd1088)),
        .wr_addr(in_addr[10:0]),
        .wr_data(in_wdata),
        .rd_en  (ct_rd_en),
        .rd_addr(ct_rd_addr),
        .rd_data(ct_rd_data)
    );

    xpm_ram_sdp_byte #(
        .ADDR_WIDTH(11),
        .DEPTH(2048),
        .READ_LATENCY(1)
    ) u_ct_prime_buf_ram (
        .clk    (clk),
        .wr_en  (core_ct_we && (core_ct_addr < 11'd1088)),
        .wr_addr(core_ct_addr),
        .wr_data(core_ct_dout),
        .rd_en  (ct_prime_rd_en),
        .rd_addr(ct_prime_rd_addr),
        .rd_data(ct_prime_rd_data)
    );

    generate
        if (HAS_INTERNAL_KECCAK) begin : gen_int_keccak
            keccak_sponge_top u_keccak (
                .clk(clk),
                .rst_n(rst_n),
                .init(shared_k_init),
                .hash_type(shared_k_hash_type),
                .finalize(shared_k_finalize),
                .din(shared_k_din),
                .din_valid(shared_k_din_valid),
                .din_ready(shared_k_din_ready),
                .dout(shared_k_dout),
                .dout_valid(shared_k_dout_valid),
                .dout_ready(shared_k_dout_ready)
            );

            assign ext_k_init       = 1'b0;
            assign ext_k_hash_type  = 2'b00;
            assign ext_k_finalize   = 1'b0;
            assign ext_k_din        = 8'd0;
            assign ext_k_din_valid  = 1'b0;
            assign ext_k_dout_ready = 1'b0;
        end else begin : gen_ext_keccak
            assign ext_k_init        = shared_k_init;
            assign ext_k_hash_type   = shared_k_hash_type;
            assign ext_k_finalize    = shared_k_finalize;
            assign ext_k_din         = shared_k_din;
            assign ext_k_din_valid   = shared_k_din_valid;
            assign shared_k_din_ready = ext_k_din_ready;
            assign shared_k_dout      = ext_k_dout;
            assign shared_k_dout_valid = ext_k_dout_valid;
            assign ext_k_dout_ready  = shared_k_dout_ready;
        end
    endgenerate

    kpke_core #(
        .HAS_INTERNAL_ENCRYPT(HAS_INTERNAL_ENCRYPT),
        .HAS_INTERNAL_POLY(HAS_INTERNAL_POLY)
    ) u_core (
        .clk(clk),
        .rst_n(rst_n),
        .start(core_start),
        .mode(core_mode),
        .busy(),
        .done(core_done),
        .in_we(core_in_we),
        .in_sel(core_in_sel),
        .in_addr(core_in_addr),
        .in_wdata(core_in_wdata),
        .m_out(core_m_out),
        .ct_we(core_ct_we),
        .ct_addr(core_ct_addr),
        .ct_dout(core_ct_dout),
        .k_init(core_k_init),
        .k_hash_type(core_k_hash_type),
        .k_finalize(core_k_finalize),
        .k_din(core_k_din),
        .k_din_valid(core_k_din_valid),
        .k_din_ready(core_k_din_ready),
        .k_dout(core_k_dout),
        .k_dout_valid(core_k_dout_valid),
        .k_dout_ready(core_k_dout_ready),
        // Shared kpke_encrypt passthrough — lifted to top-level when
        // HAS_INTERNAL_ENCRYPT==0. When HAS_INTERNAL_ENCRYPT==1, kpke_core
        // ties forward outputs to 0 and ignores backward inputs.
        .ext_enc_start    (ext_enc_start),
        .ext_enc_in_we    (ext_enc_in_we),
        .ext_enc_in_sel   (ext_enc_in_sel),
        .ext_enc_in_addr  (ext_enc_in_addr),
        .ext_enc_in_wdata (ext_enc_in_wdata),
        .ext_enc_busy     (ext_enc_busy),
        .ext_enc_done     (ext_enc_done),
        .ext_enc_ct_we    (ext_enc_ct_we),
        .ext_enc_ct_addr  (ext_enc_ct_addr),
        .ext_enc_ct_dout  (ext_enc_ct_dout),
        .ext_dec_fromb_start(ext_dec_fromb_start),
        .ext_dec_fromb_done(ext_dec_fromb_done),
        .ext_dec_fromb_byte_addr(ext_dec_fromb_byte_addr),
        .ext_dec_fromb_byte_din(ext_dec_fromb_byte_din),
        .ext_dec_fromb_coeff_we(ext_dec_fromb_coeff_we),
        .ext_dec_fromb_coeff_addr(ext_dec_fromb_coeff_addr),
        .ext_dec_fromb_coeff_a0(ext_dec_fromb_coeff_a0),
        .ext_dec_fromb_coeff_a1(ext_dec_fromb_coeff_a1),
        .ext_dec_ntt_start(ext_dec_ntt_start),
        .ext_dec_ntt_done(ext_dec_ntt_done),
        .ext_dec_ntt_host_we(ext_dec_ntt_host_we),
        .ext_dec_ntt_host_addr(ext_dec_ntt_host_addr),
        .ext_dec_ntt_host_din(ext_dec_ntt_host_din),
        .ext_dec_ntt_host_dout(ext_dec_ntt_host_dout),
        .ext_dec_intt_start(ext_dec_intt_start),
        .ext_dec_intt_done(ext_dec_intt_done),
        .ext_dec_intt_host_we(ext_dec_intt_host_we),
        .ext_dec_intt_host_addr(ext_dec_intt_host_addr),
        .ext_dec_intt_host_din(ext_dec_intt_host_din),
        .ext_dec_intt_host_dout(ext_dec_intt_host_dout),
        .ext_dec_pw_start(ext_dec_pw_start),
        .ext_dec_pw_done(ext_dec_pw_done),
        .ext_dec_pw_host_sel(ext_dec_pw_host_sel),
        .ext_dec_pw_host_we(ext_dec_pw_host_we),
        .ext_dec_pw_host_addr(ext_dec_pw_host_addr),
        .ext_dec_pw_host_din(ext_dec_pw_host_din),
        .ext_dec_pw_host_dout(ext_dec_pw_host_dout),
        .ext_dec_add_start(ext_dec_add_start),
        .ext_dec_add_is_sub(ext_dec_add_is_sub),
        .ext_dec_add_done(ext_dec_add_done),
        .ext_dec_add_host_sel(ext_dec_add_host_sel),
        .ext_dec_add_host_we(ext_dec_add_host_we),
        .ext_dec_add_host_addr(ext_dec_add_host_addr),
        .ext_dec_add_host_din(ext_dec_add_host_din),
        .ext_dec_add_host_dout(ext_dec_add_host_dout),
        .ext_dec_comp_start(ext_dec_comp_start),
        .ext_dec_comp_d_sel(ext_dec_comp_d_sel),
        .ext_dec_comp_done(ext_dec_comp_done),
        .ext_dec_comp_coeff_addr(ext_dec_comp_coeff_addr),
        .ext_dec_comp_coeff_a0(ext_dec_comp_coeff_a0),
        .ext_dec_comp_coeff_a1(ext_dec_comp_coeff_a1),
        .ext_dec_comp_byte_we(ext_dec_comp_byte_we),
        .ext_dec_comp_byte_addr(ext_dec_comp_byte_addr),
        .ext_dec_comp_byte_dout(ext_dec_comp_byte_dout)
    );

    // Capture h/z slices from incoming decapsulation key stream.
    always @(posedge clk) begin
        if (in_we && !busy && !in_sel) begin
            if ((in_addr >= 12'd2336) && (in_addr < 12'd2368)) begin
                h_reg[in_addr - 12'd2336] <= in_wdata;
            end else if ((in_addr >= 12'd2368) && (in_addr < 12'd2400)) begin
                z_reg[in_addr - 12'd2368] <= in_wdata;
            end
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state            <= S_IDLE;
            busy             <= 1'b0;
            done             <= 1'b0;
            out_rdata        <= 8'd0;
            out_valid        <= 1'b0;
            ss_out           <= 256'd0;
            k_prime_vec      <= 256'd0;
            k_reject_vec     <= 256'd0;

            init_keccak      <= 1'b0;
            hash_type        <= 2'b00;
            finalize_keccak  <= 1'b0;
            k_din            <= 8'd0;
            k_din_valid      <= 1'b0;
            fsm_k_dout_ready <= 1'b0;

            core_start       <= 1'b0;
            core_mode        <= 2'd0;
            core_in_we       <= 1'b0;
            core_in_sel      <= 2'd0;
            core_in_addr     <= 11'd0;
            core_in_wdata    <= 8'd0;

            dk_rd_en         <= 1'b0;
            dk_rd_addr       <= 11'd0;
            ek_rd_en         <= 1'b0;
            ek_rd_addr       <= 11'd0;
            ct_rd_en         <= 1'b0;
            ct_rd_addr       <= 11'd0;
            ct_prime_rd_en   <= 1'b0;
            ct_prime_rd_addr <= 11'd0;

            var_k            <= 12'd0;
            xor_acc          <= 8'd0;
            match_reg        <= 1'b0;
            enc_ct_last_seen <= 1'b0;
            dbg_cmp_idx      <= 11'd0;
            dbg_ct_byte      <= 8'd0;
            dbg_ct_prime_byte<= 8'd0;
            dbg_cmp_seen     <= 1'b0;
            dbg_enc_ct_count <= 12'd0;
            for (i = 0; i < 32; i = i + 1) begin
                m_prime[i]  <= 8'd0;
                k_prime[i]  <= 8'd0;
                r_prime[i]  <= 8'd0;
                k_reject[i] <= 8'd0;
                ss_buf[i]   <= 8'd0;
            end
        end else begin
            done             <= 1'b0;
            out_valid        <= 1'b0;
            init_keccak      <= 1'b0;
            finalize_keccak  <= 1'b0;
            k_din_valid      <= 1'b0;
            core_start       <= 1'b0;
            core_in_we       <= 1'b0;
            dk_rd_en         <= 1'b0;
            ek_rd_en         <= 1'b0;
            ct_rd_en         <= 1'b0;
            ct_prime_rd_en   <= 1'b0;

            if (out_rd) begin
                out_valid <= 1'b1;
                if (out_addr < 11'd32) out_rdata <= ss_buf[out_addr[4:0]];
                else                    out_rdata <= 8'd0;
            end
            if (core_ct_we && (core_ct_addr < 11'd1088) && (core_ct_addr == 11'd1087)) begin
                enc_ct_last_seen <= 1'b1;
            end
            if (core_ct_we && (core_ct_addr < 11'd1088)) begin
                dbg_enc_ct_count <= dbg_enc_ct_count + 12'd1;
            end

            case (state)
                S_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        busy    <= 1'b1;
                        core_mode <= 2'd0;
                        var_k   <= 12'd0;
                        xor_acc <= 8'd0;
                        match_reg <= 1'b0;
                        enc_ct_last_seen <= 1'b0;
                        dbg_cmp_idx       <= 11'd0;
                        dbg_ct_byte       <= 8'd0;
                        dbg_ct_prime_byte <= 8'd0;
                        dbg_cmp_seen      <= 1'b0;
                        dbg_enc_ct_count  <= 12'd0;
                        for (i = 0; i < 32; i = i + 1) begin
                            m_prime[i]  <= 8'd0;
                            k_prime[i]  <= 8'd0;
                            r_prime[i]  <= 8'd0;
                            k_reject[i] <= 8'd0;
                            ss_buf[i]   <= 8'd0;
                            ss_out[i*8 +: 8] <= 8'd0;
                        end
                        k_prime_vec <= 256'd0;
                        k_reject_vec <= 256'd0;
                        state <= S_DEC_PRELOAD_REQ;
                    end
                end

                // Preload kpke_decrypt with dk_PKE || ct
                S_DEC_PRELOAD: begin
                    state <= S_DEC_PRELOAD_REQ;
                end

                S_DEC_PRELOAD_REQ: begin
                    core_mode <= 2'd0;
                    if (var_k < 12'd1152) begin
                        dk_rd_en   <= 1'b1;
                        dk_rd_addr <= var_k[10:0];
                        state      <= S_DEC_PRELOAD_WAIT;
                    end else if (var_k < 12'd2240) begin
                        ct_rd_en   <= 1'b1;
                        ct_rd_addr <= var_k[10:0] - 11'd1152;
                        state      <= S_DEC_PRELOAD_WAIT;
                    end else begin
                        var_k <= 12'd0;
                        state <= S_DEC_START;
                    end
                end

                S_DEC_PRELOAD_WAIT: begin
                    state <= S_DEC_PRELOAD_SEND;
                end

                S_DEC_PRELOAD_SEND: begin
                    core_mode <= 2'd0;
                    core_in_we <= 1'b1;
                    if (var_k < 12'd1152) begin
                        core_in_sel   <= 2'd0;
                        core_in_addr  <= var_k[10:0];
                        core_in_wdata <= dk_rd_data;
                    end else begin
                        core_in_sel   <= 2'd1;
                        core_in_addr  <= var_k[10:0] - 11'd1152;
                        core_in_wdata <= ct_rd_data;
                    end

                    if (var_k == 12'd2239) begin
                        var_k <= 12'd0;
                        state <= S_DEC_START;
                    end else begin
                        var_k <= var_k + 12'd1;
                        state <= S_DEC_PRELOAD_REQ;
                    end
                end

                S_DEC_START: begin
                    core_mode  <= 2'd0;
                    core_start <= 1'b1;
                    state <= S_DEC_WAIT;
                end

                S_DEC_WAIT: begin
                    if (core_done) begin
                        state <= S_CAPTURE_M;
                    end
                end

                S_CAPTURE_M: begin
                    for (i = 0; i < 32; i = i + 1) begin
                        m_prime[i] <= core_m_out[i*8 +: 8];
                    end
                    var_k <= 12'd0;
                    state <= S_HASH_G_INIT;
                end

                // (K', r') = SHA3-512(m' || h)
                S_HASH_G_INIT: begin
                    init_keccak <= 1'b1;
                    hash_type   <= 2'b11; // SHA3-512
                    var_k       <= 12'd0;
                    k_din       <= m_prime[5'd0];
                    k_din_valid <= 1'b1;
                    state       <= S_HASH_G_ABS;
                end

                S_HASH_G_ABS: begin
                    k_din_valid <= 1'b1;
                    if (k_din_ready) begin
                        if (var_k == 12'd63) begin
                            k_din_valid <= 1'b0;
                            state <= S_HASH_G_FIN;
                        end else begin
                            var_k <= var_k + 12'd1;
                            if (var_k < 12'd31) begin
                                k_din <= m_prime[var_k[4:0] + 5'd1];
                            end else begin
                                k_din <= h_reg[var_k - 12'd31];
                            end
                        end
                    end
                end

                S_HASH_G_FIN: begin
                    finalize_keccak  <= 1'b1;
                    fsm_k_dout_ready <= 1'b1;
                    var_k            <= 12'd0;
                    state            <= S_HASH_G_WAIT;
                end

                S_HASH_G_WAIT: begin
                    if (k_dout_valid && fsm_k_dout_ready) begin
                        if (var_k < 12'd32) begin
                            k_prime[var_k[4:0]] <= k_dout;
                            k_prime_vec[var_k[4:0]*8 +: 8] <= k_dout;
                        end else begin
                            r_prime[var_k - 12'd32] <= k_dout;
                        end
                        if (var_k == 12'd63) begin
                            fsm_k_dout_ready <= 1'b0;
                            var_k <= 12'd0;
                            state <= S_HASH_J_INIT;
                        end else begin
                            var_k <= var_k + 12'd1;
                        end
                    end
                end

                // K_reject = SHAKE-256(z || ct)
                S_HASH_J_INIT: begin
                    init_keccak <= 1'b1;
                    hash_type   <= 2'b01; // SHAKE-256
                    var_k       <= 12'd0;
                    k_din       <= z_reg[5'd0];
                    k_din_valid <= 1'b1;
                    state       <= S_HASH_J_ABS;
                end

                S_HASH_J_ABS: begin
                    k_din_valid <= 1'b1;
                    if (k_din_ready) begin
                        if (var_k == 12'd1119) begin
                            k_din_valid <= 1'b0;
                            state <= S_HASH_J_FIN;
                        end else begin
                            if (var_k < 12'd31) begin
                                var_k <= var_k + 12'd1;
                                k_din <= z_reg[var_k[4:0] + 5'd1];
                            end else begin
                                var_k    <= var_k + 12'd1;
                                ct_rd_en <= 1'b1;
                                ct_rd_addr <= var_k[10:0] - 11'd31;
                                state    <= S_HASH_J_CT_WAIT;
                            end
                        end
                    end
                end

                S_HASH_J_CT_WAIT: begin
                    state <= S_HASH_J_CT_SEND;
                end

                S_HASH_J_CT_SEND: begin
                    k_din       <= ct_rd_data;
                    state <= S_HASH_J_ABS;
                end

                S_HASH_J_FIN: begin
                    finalize_keccak  <= 1'b1;
                    fsm_k_dout_ready <= 1'b1;
                    var_k            <= 12'd0;
                    state            <= S_HASH_J_WAIT;
                end

                S_HASH_J_WAIT: begin
                    if (k_dout_valid && fsm_k_dout_ready) begin
                        k_reject[var_k[4:0]] <= k_dout;
                        k_reject_vec[var_k[4:0]*8 +: 8] <= k_dout;
                        if (var_k == 12'd31) begin
                            fsm_k_dout_ready <= 1'b0;
                            var_k <= 12'd0;
                            state <= S_ENC_PRELOAD;
                        end else begin
                            var_k <= var_k + 12'd1;
                        end
                    end
                end

                // Preload kpke_encrypt with ek || m' || r'
                S_ENC_PRELOAD: begin
                    core_mode <= 2'd1;
                    if (var_k < 12'd1184) begin
                        ek_rd_en   <= 1'b1;
                        ek_rd_addr <= var_k[10:0];
                        state      <= S_ENC_PRELOAD_EK_WAIT;
                    end else if (var_k < 12'd1216) begin
                        core_in_we    <= 1'b1;
                        core_in_sel   <= 2'd1;
                        core_in_addr  <= var_k[10:0] - 11'd1184;
                        core_in_wdata <= m_prime[var_k - 12'd1184];
                        var_k        <= var_k + 12'd1;
                    end else if (var_k < 12'd1248) begin
                        core_in_we    <= 1'b1;
                        core_in_sel   <= 2'd2;
                        core_in_addr  <= var_k[10:0] - 11'd1216;
                        core_in_wdata <= r_prime[var_k - 12'd1216];
                        if (var_k == 12'd1247) begin
                            var_k <= 12'd0;
                            state <= S_ENC_START;
                        end else begin
                            var_k <= var_k + 12'd1;
                        end
                    end else begin
                        var_k <= 12'd0;
                        state <= S_ENC_START;
                    end
                end

                S_ENC_PRELOAD_EK_WAIT: begin
                    state <= S_ENC_PRELOAD_EK_SEND;
                end

                S_ENC_PRELOAD_EK_SEND: begin
                    core_mode <= 2'd1;
                    core_in_we    <= 1'b1;
                    core_in_sel   <= 2'd0;
                    core_in_addr  <= var_k[10:0];
                    core_in_wdata <= ek_rd_data;
                    var_k        <= var_k + 12'd1;
                    state        <= S_ENC_PRELOAD;
                end

                S_ENC_START: begin
                    enc_ct_last_seen <= 1'b0;
                    core_mode  <= 2'd1;
                    core_start <= 1'b1;
                    state <= S_ENC_WAIT;
                end

                S_ENC_WAIT: begin
                    if (core_done) begin
                        var_k <= 12'd0;
                        if (enc_ct_last_seen) begin
                            state <= S_COMPARE_INIT;
                        end else begin
                            state <= S_ENC_SETTLE;
                        end
                    end
                end

                S_ENC_SETTLE: begin
                    if (enc_ct_last_seen || (var_k == 12'd4095)) begin
                        state <= S_COMPARE_INIT;
                    end else begin
                        var_k <= var_k + 12'd1;
                    end
                end

                // Constant-time compare: XOR-accumulate all 1088 bytes
                S_COMPARE_INIT: begin
                    xor_acc <= 8'd0;
                    var_k   <= 12'd0;
                    state   <= S_COMPARE_REQ;
                end

                S_COMPARE_REQ: begin
                    ct_rd_en         <= 1'b1;
                    ct_rd_addr       <= var_k[10:0];
                    ct_prime_rd_en   <= 1'b1;
                    ct_prime_rd_addr <= var_k[10:0];
                    state            <= S_COMPARE_WAIT;
                end

                S_COMPARE_WAIT: begin
                    state <= S_COMPARE;
                end

                S_COMPARE: begin
                    xor_acc <= compare_xor_next;
                    if (!dbg_cmp_seen && (compare_xor_byte != 8'd0)) begin
                        dbg_cmp_seen      <= 1'b1;
                        dbg_cmp_idx       <= var_k[10:0];
                        dbg_ct_byte       <= ct_rd_data;
                        dbg_ct_prime_byte <= ct_prime_rd_data;
                    end
                    if (var_k == 12'd1087) begin
                        match_reg <= (compare_xor_next == 8'd0);
                        var_k <= 12'd0;
                        state <= S_OUTPUT;
                    end else begin
                        var_k <= var_k + 12'd1;
                        state <= S_COMPARE_REQ;
                    end
                end

                // Constant-time MUX output
                S_OUTPUT: begin
                    ss_out <= (k_prime_vec & {256{match_reg}}) | (k_reject_vec & {256{~match_reg}});
                    for (i = 0; i < 32; i = i + 1) begin
                        ss_buf[i] <= (k_prime_vec[i*8 +: 8] & match_mask) |
                                     (k_reject_vec[i*8 +: 8] & ~match_mask);
                    end
                    var_k <= 12'd0;
                    state <= S_ZEROIZE;
                end

                // Zeroize sensitive intermediates
                S_ZEROIZE: begin
                    m_prime[var_k[4:0]] <= 8'd0;
                    r_prime[var_k[4:0]] <= 8'd0;
                    k_prime[var_k[4:0]] <= 8'd0;
                    if (var_k == 12'd31) begin
                        var_k <= 12'd0;
                        state <= S_DONE;
                    end else begin
                        var_k <= var_k + 12'd1;
                    end
                end

                S_DONE: begin
                    busy <= 1'b0;
                    done <= 1'b1;
                    state <= S_IDLE;
                end

                default: begin
                    var_k <= 12'd0;
                    state <= S_ZEROIZE;
                end
            endcase
        end
    end

endmodule
