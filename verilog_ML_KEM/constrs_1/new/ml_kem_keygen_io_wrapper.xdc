# ============================================================================
# ML-KEM KeyGen IO Wrapper - Baseline Timing Constraints
# Top module: ml_kem_keygen_io_wrapper
#
# NOTE:
# - This file provides a practical baseline for timing analysis closure.
# - The I/O delays below are placeholder board-level values.
#   Replace them with interface-specific timing from your real board/spec.
# ============================================================================

# ----------------------------------------------------------------------------
# Primary clock
# ----------------------------------------------------------------------------
create_clock -name clk -period 10.000 [get_ports clk]

# ----------------------------------------------------------------------------
# I/O timing model (placeholder values for board-level STA)
# ----------------------------------------------------------------------------
# Keep min/max different so STA reflects PVT/jitter window.
set keygen_in_ports  [get_ports {start seed_we seed_sel seed_addr[*] seed_wdata[*] out_rd out_sel out_addr[*]}]
set keygen_out_ports [get_ports {busy done out_rdata[*] out_valid}]

set_input_delay  -clock [get_clocks clk] -max 2.000 $keygen_in_ports
set_input_delay  -clock [get_clocks clk] -min 0.500 $keygen_in_ports

set_output_delay -clock [get_clocks clk] -max 2.000 $keygen_out_ports
set_output_delay -clock [get_clocks clk] -min 0.500 $keygen_out_ports

# Optional nominal delay on async reset to keep methodology checks clean.
set_input_delay  -clock [get_clocks clk] -max 2.000 [get_ports rst_n]
set_input_delay  -clock [get_clocks clk] -min 0.500 [get_ports rst_n]

# ----------------------------------------------------------------------------
# Asynchronous reset path exclusion
# ----------------------------------------------------------------------------
set_false_path -from [get_ports rst_n]
