# ============================================================================
# ML-KEM KeyGen IO Wrapper - Baseline Timing Constraints
# Top module: ml_kem_keygen_io_wrapper
#
# NOTE:
# - This file provides a practical baseline for timing analysis closure.
# - The I/O delays below are placeholder board-level values (2.0 ns).
#   Replace them with interface-specific timing from your real board/spec.
# ============================================================================

# ----------------------------------------------------------------------------
# Primary clock
# ----------------------------------------------------------------------------
create_clock -name clk -period 10.000 [get_ports clk]

# ----------------------------------------------------------------------------
# Asynchronous reset path exclusion
# ----------------------------------------------------------------------------
set_false_path -from [get_ports rst_n]

# ----------------------------------------------------------------------------
# Baseline I/O timing constraints
# ----------------------------------------------------------------------------
# Exclude clk and async reset from generic input delay constraints.
set_input_delay  2.000 -clock [get_clocks clk] \
    [remove_from_collection [all_inputs] [get_ports {clk rst_n}]]

set_output_delay 2.000 -clock [get_clocks clk] [all_outputs]

