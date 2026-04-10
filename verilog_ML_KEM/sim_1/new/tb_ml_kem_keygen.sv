`timescale 1ns / 1ps

module tb_ml_kem_keygen();

    // Clock and Reset
    reg clk;
    reg rst_n;
    
    // Inputs
    reg         start;
    reg [255:0] seed_d; // 32 bytes
    reg [255:0] seed_z; // 32 bytes
    
    // Outputs
    wire        done;
    wire        pk_we;
    wire [10:0] pk_addr;
    wire [7:0]  pk_dout;
    
    wire        sk_we;
    wire [11:0] sk_addr;
    wire [7:0]  sk_dout;
    
    // Instantiate DUT
    ml_kem_keygen dut (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .done(done),
        .seed_d_in(seed_d),
        .seed_z_in(seed_z),
        .pk_we(pk_we),
        .pk_addr(pk_addr),
        .pk_dout(pk_dout),
        .sk_we(sk_we),
        .sk_addr(sk_addr),
        .sk_dout(sk_dout)
    );
    
    // Clock generation
    always #5 clk = ~clk; // 100MHz
    
    // local memories for output capturing
    reg [7:0] pk_mem [0:1183];
    reg [7:0] sk_mem [0:2399];
    
    always @(posedge clk) begin
        if (pk_we) pk_mem[pk_addr] <= pk_dout;
        if (sk_we) sk_mem[sk_addr] <= sk_dout;
    end
    
    // Expected memories
    reg [7:0] expected_pk [0:1183];
    reg [7:0] expected_sk [0:2399];
    
    logic pk_fail;
    always @(posedge clk) begin
        if (pk_we && pk_addr < 2 && pk_dout === 8'hxx) begin
            $display("[DEBUG] Writing to pk_mem[%0d] = %h", pk_addr, pk_dout);
        end
        if (dut.state == 33 && dut.pump_cnt < 3) begin // S_PUMP=33
            $display("[PUMP] src=%0d, dst=%0d, i=%0d, j=%0d, addr=%0d, data=%h", 
                dut.pump_src_sel, dut.pump_dst_sel, dut.i_idx, dut.j_idx, dut.pump_rd_addr, dut.pump_read_data);
        end
    end

    // Read hex parsing helper
    function int hex_char_to_val(input byte c);
        if (c >= "0" && c <= "9") return c - "0";
        if (c >= "a" && c <= "f") return c - "a" + 10;
        if (c >= "A" && c <= "F") return c - "A" + 10;
        return 0;
    endfunction

    // Test sequence
    integer fd, status, i;
    string line;
    byte hex_char1, hex_char2;
    int data_val;
    int cycle_count;

    initial begin
        clk = 0;
        rst_n = 0;
        start = 0;
        
        #20 rst_n = 1;
        
        // Vivado run directory is inside .sim/sim_1/behav/xsim, 
        // using absolute path is the safest way to avoid open fails
        fd = $fopen("D:/HCMUT/Year_4/252/CA/Source/DACN/vitis_ML_KEM/src/KAT_768.txt", "r");
        if (fd == 0) begin
            $display("ERROR: Cannot open D:/HCMUT/Year_4/252/CA/Source/DACN/vitis_ML_KEM/src/KAT_768.txt");
            $finish;
        end
        
        $display("======= ML-KEM-768 RTL Verification ========");
        
        // Read first KAT vector
        while (!$feof(fd)) begin
            status = $fgets(line, fd);
            if (line.substr(0, 3) == "d = ") begin
                for (i = 0; i < 32; i++) begin
                    data_val = (hex_char_to_val(line[4 + i*2]) << 4) | hex_char_to_val(line[4 + i*2 + 1]);
                    // Pack into 256-bit array
                    seed_d[i*8 +: 8] = data_val;
                end
            end
            else if (line.substr(0, 3) == "z = ") begin
                for (i = 0; i < 32; i++) begin
                    data_val = (hex_char_to_val(line[4 + i*2]) << 4) | hex_char_to_val(line[4 + i*2 + 1]);
                    seed_z[i*8 +: 8] = data_val;
                end
            end
            else if (line.substr(0, 4) == "pk = ") begin
                for (i = 0; i < 1184; i++) begin
                    expected_pk[i] = (hex_char_to_val(line[5 + i*2]) << 4) | hex_char_to_val(line[5 + i*2 + 1]);
                end
            end
            else if (line.substr(0, 4) == "sk = ") begin
                for (i = 0; i < 2400; i++) begin
                    expected_sk[i] = (hex_char_to_val(line[5 + i*2]) << 4) | hex_char_to_val(line[5 + i*2 + 1]);
                end
                
                // Finished parsing 1 vector, run test
                $display("Starting KeyGen...");
                
                @(posedge clk);
                start = 1;
                @(posedge clk);
                start = 0;
                
                cycle_count = 0;
                while (!done) begin
                    @(posedge clk);
                    cycle_count++;
                end
                
                $display("KeyGen Done in %0d cycles.", cycle_count);
                
                // Verify PK
                pk_fail = 0;
                for (i = 0; i < 1184; i = i + 1) begin
                    if (pk_mem[i] !== expected_pk[i]) begin
                        $display("PK Mismatch at byte %0d: Expected %02x, Got %02x", i, expected_pk[i], pk_mem[i]);
                        $stop;
                    end
                end
                $display("PK Match: PASSED");

                // Compare SK
                for (i = 0; i < 2400; i++) begin
                    if (sk_mem[i] !== expected_sk[i]) begin
                        $display("SK Mismatch at byte %0d: Expected %02x, Got %02x", i, expected_sk[i], sk_mem[i]);
                        $stop;
                    end
                end
                $display("SK Match: PASSED");
                
                $display("TEST PASSED FOR 1 KAT!");
                $finish;
            end
        end
        
        $fclose(fd);
        $finish;
    end

endmodule
