# KR260 PL clock target: 100 MHz
create_clock -name clk_pl -period 10.000 [get_ports clk]

# AXI interfaces in same clock domain (`clk`), keep default timing analysis.
# Add board-specific pin constraints in the Vivado block design / wrapper level.
