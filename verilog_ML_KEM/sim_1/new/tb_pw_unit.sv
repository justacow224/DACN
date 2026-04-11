`timescale 1ns/1ps

module tb_pw_unit;
  reg clk = 0;
  reg rst_n = 0;
  reg start = 0;
  wire done;

  reg host_sel = 0;
  reg host_we = 0;
  reg [7:0] host_addr = 0;
  reg [15:0] host_din = 0;
  wire [15:0] host_dout;

  poly_pointwise_top dut (
    .clk(clk), .rst_n(rst_n), .start(start), .done(done),
    .host_sel(host_sel), .host_we(host_we), .host_addr(host_addr), .host_din(host_din), .host_dout(host_dout)
  );

  always #5 clk = ~clk;

  task write_ram(input sel, input [7:0] addr, input [15:0] data);
    begin
      @(posedge clk);
      host_sel  <= sel;
      host_addr <= addr;
      host_din  <= data;
      host_we   <= 1'b1;
      @(posedge clk);
      host_we   <= 1'b0;
    end
  endtask

  task read_a(input [7:0] addr, output [15:0] data);
    begin
      @(posedge clk);
      host_sel  <= 1'b0;
      host_addr <= addr;
      host_we   <= 1'b0;
      @(posedge clk);
      @(posedge clk);
      data = host_dout;
    end
  endtask

  reg [15:0] r0, r1, r2, r3;

  initial begin
    repeat (3) @(posedge clk);
    rst_n <= 1'b1;

    // a0,a1 in RAM A
    write_ram(1'b0, 8'd0, 16'h066c);
    write_ram(1'b0, 8'd1, 16'h0b2d);

    // b0,b1 in RAM B
    write_ram(1'b1, 8'd0, 16'h0ada);
    write_ram(1'b1, 8'd1, 16'h0c70);

    @(posedge clk);
    start <= 1'b1;
    @(posedge clk);
    start <= 1'b0;

    wait(done == 1'b1);

    read_a(8'd0, r0);
    read_a(8'd1, r1);
    read_a(8'd2, r2);
    read_a(8'd3, r3);

    $display("PW unit result: r0=%h r1=%h r2=%h r3=%h", r0, r1, r2, r3);
    $display("Expected pair0: r0=0596 r1=0b1b");

    if (r0 !== 16'h0596 || r1 !== 16'h0b1b) begin
      $display("MISMATCH");
      $stop;
    end

    $display("PASS");
    $finish;
  end
endmodule
