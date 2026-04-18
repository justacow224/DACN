`timescale 1ns / 1ps

module inv_zeta_rom (
    input  wire         clk,
    input  wire         en,
    input  wire [6:0]   addr,  // 128 elements -> 7-bit address (0 to 127)
    output reg  [15:0]  dout = 16'd0
);

    reg [15:0] rom [0:127];

    initial begin
        rom[0]   = 16'd0;    rom[1]   = 16'd1600; rom[2]   = 16'd749;  rom[3]   = 16'd40;   rom[4]   = 16'd687;  rom[5]   = 16'd2699; rom[6]   = 16'd1432; rom[7]   = 16'd2481;
        rom[8]   = 16'd2267; rom[9]   = 16'd1410; rom[10]  = 16'd3136; rom[11]  = 16'd2532; rom[12]  = 16'd543;  rom[13]  = 16'd69;   rom[14]  = 16'd2760; rom[15]  = 16'd1583;
        rom[16]  = 16'd3033; rom[17]  = 16'd882;  rom[18]  = 16'd1990; rom[19]  = 16'd1853; rom[20]  = 16'd283;  rom[21]  = 16'd3273; rom[22]  = 16'd1089; rom[23]  = 16'd1996;
        rom[24]  = 16'd1903; rom[25]  = 16'd1235; rom[26]  = 16'd2794; rom[27]  = 16'd447;  rom[28]  = 16'd936;  rom[29]  = 16'd450;  rom[30]  = 16'd1355; rom[31]  = 16'd2508;
        rom[32]  = 16'd3040; rom[33]  = 16'd2998; rom[34]  = 16'd76;   rom[35]  = 16'd1573; rom[36]  = 16'd2132; rom[37]  = 16'd1025; rom[38]  = 16'd1052; rom[39]  = 16'd1274;
        rom[40]  = 16'd2679; rom[41]  = 16'd1352; rom[42]  = 16'd816;  rom[43]  = 16'd2697; rom[44]  = 16'd464;  rom[45]  = 16'd3296; rom[46]  = 16'd2009; rom[47]  = 16'd1414;
        rom[48]  = 16'd1010; rom[49]  = 16'd1894; rom[50]  = 16'd2522; rom[51]  = 16'd2877; rom[52]  = 16'd1891; rom[53]  = 16'd461;  rom[54]  = 16'd1795; rom[55]  = 16'd927;
        rom[56]  = 16'd682;  rom[57]  = 16'd712;  rom[58]  = 16'd1848; rom[59]  = 16'd2681; rom[60]  = 16'd855;  rom[61]  = 16'd219;  rom[62]  = 16'd2102; rom[63]  = 16'd2419;
        rom[64]  = 16'd3312; rom[65]  = 16'd568;  rom[66]  = 16'd2746; rom[67]  = 16'd680;  rom[68]  = 16'd1692; rom[69]  = 16'd2606; rom[70]  = 16'd1041; rom[71]  = 16'd2229;
        rom[72]  = 16'd1920; rom[73]  = 16'd667;  rom[74]  = 16'd48;   rom[75]  = 16'd3096; rom[76]  = 16'd2573; rom[77]  = 16'd1173; rom[78]  = 16'd314;  rom[79]  = 16'd279;
        rom[80]  = 16'd1626; rom[81]  = 16'd1678; rom[82]  = 16'd540;  rom[83]  = 16'd1540; rom[84]  = 16'd1482; rom[85]  = 16'd2377; rom[86]  = 16'd1868; rom[87]  = 16'd642;
        rom[88]  = 16'd2390; rom[89]  = 16'd1021; rom[90]  = 16'd892;  rom[91]  = 16'd941;  rom[92]  = 16'd2596; rom[93]  = 16'd992;  rom[94]  = 16'd3061; rom[95]  = 16'd2688;
        rom[96]  = 16'd1745; rom[97]  = 16'd1031; rom[98]  = 16'd1292; rom[99]  = 16'd109;  rom[100] = 16'd2954; rom[101] = 16'd780;  rom[102] = 16'd1239; rom[103] = 16'd1684;
        rom[104] = 16'd2266; rom[105] = 16'd3010; rom[106] = 16'd556;  rom[107] = 16'd2572; rom[108] = 16'd1230; rom[109] = 16'd2768; rom[110] = 16'd863;  rom[111] = 16'd735;
        rom[112] = 16'd525;  rom[113] = 16'd2237; rom[114] = 16'd2926; rom[115] = 16'd2303; rom[116] = 16'd2186; rom[117] = 16'd1179; rom[118] = 16'd554;  rom[119] = 16'd2443;
        rom[120] = 16'd1607; rom[121] = 16'd2117; rom[122] = 16'd1455; rom[123] = 16'd2300; rom[124] = 16'd1219; rom[125] = 16'd394;  rom[126] = 16'd2444; rom[127] = 16'd1175;
    end

    // Synchronous read (1 clock cycle latency)
    always @(posedge clk) begin
        if (en) begin
            dout <= rom[addr];
        end else begin
            dout <= 16'd0;
        end
    end

endmodule
