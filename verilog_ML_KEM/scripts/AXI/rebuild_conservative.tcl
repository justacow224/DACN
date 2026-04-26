# ==============================================================================
# Rebuild bitstream with CONSERVATIVE synth strategy (debug aid)
# ==============================================================================
# Purpose: isolate whether the on-board encaps ct mismatch is caused by
# aggressive Vivado optimization. We disable retiming, hierarchy flattening,
# and resource sharing — keeping RTL structure as close to behavioral sim
# as possible. If KAT passes with this build, root cause is optimization.
# If still fails, the bug is elsewhere (AXI race, BRAM init, etc.).
#
# EXECUTION:
#   "C:/Xilinx/2025.1/Vivado/bin/vivado.bat" -mode batch \
#     -source verilog_ML_KEM/scripts/AXI/rebuild_conservative.tcl \
#     -tclargs D:/HCMUT/Year_4/252/CA/Vivado/verilog_ML_KEM/verilog_ML_KEM.xpr
# ==============================================================================

if {[llength $argv] < 1} {
    puts "ERROR: Missing project path"
    exit 1
}

set xpr_path [file normalize [lindex $argv 0]]
open_project $xpr_path

# CRITICAL: set top BEFORE strategy change (some strategy resets clobber it).
# Without this, synth_1 picks ml_kem_top (268 IO ports) instead of
# ml_kem_bd_wrapper, and IO placement fails with [Place 30-58].
set_property top ml_kem_bd_wrapper [current_fileset]
update_compile_order -fileset sources_1

# Save current strategy so we can restore later
set orig_strat [get_property STRATEGY [get_runs synth_1]]
puts "INFO: original synth_1 strategy: $orig_strat"
puts "INFO: top fileset: [get_property top [current_fileset]]"

# Apply conservative synth options
set_property STRATEGY "Vivado Synthesis Defaults" [get_runs synth_1]
# Re-set top after strategy change in case it got clobbered
set_property top ml_kem_bd_wrapper [current_fileset]
set_property -name {STEPS.SYNTH_DESIGN.ARGS.FLATTEN_HIERARCHY} -value {none} -objects [get_runs synth_1]
set_property -name {STEPS.SYNTH_DESIGN.ARGS.NO_LC}            -value {true} -objects [get_runs synth_1]
set_property -name {STEPS.SYNTH_DESIGN.ARGS.RETIMING}         -value {false} -objects [get_runs synth_1]
set_property -name {STEPS.SYNTH_DESIGN.ARGS.RESOURCE_SHARING} -value {off} -objects [get_runs synth_1]

puts "INFO: applied conservative synth options:"
puts "  flatten_hierarchy = none"
puts "  no_lc             = true (disable LUT combining)"
puts "  retiming          = false"
puts "  resource_sharing  = off"

reset_run synth_1
launch_runs impl_1 -to_step write_bitstream -jobs 8
wait_on_run impl_1

set status [get_property STATUS [get_runs impl_1]]
puts "INFO: impl_1 status: $status"

if {[string first "write_bitstream Complete" $status] < 0} {
    puts "ERROR: bitstream not generated. impl_1 status = $status"
    close_project
    exit 2
}

# Quick sanity: verify stage_d1_reg still survives (should, with no_lc + dont_touch)
open_run impl_1
set survivors [get_cells -hier -filter {NAME =~ *u_inv_ntt*stage_d1_reg*}]
puts "INFO: surviving stage_d1_reg instances: [llength $survivors]"

set wns [get_property SLACK [get_timing_paths -max_paths 1 -delay_type max]]
puts "INFO: WNS = $wns ns"

set util [report_utilization -return_string -hierarchical_depth 1]
puts "INFO: utilization (top level):"
foreach line [split $util "\n"] {
    if {[regexp {(LUT|LUTRAM|FF|BRAM|DSP)\s} $line]} {
        puts "  $line"
    }
}

set bit_path [glob -nocomplain [file join [get_property DIRECTORY [current_project]] "*.runs/impl_1/*.bit"]]
puts "INFO: bitstream -> $bit_path"

close_project
exit 0
