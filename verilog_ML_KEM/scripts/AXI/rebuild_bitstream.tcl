# ==============================================================================
# Rebuild bitstream after RTL fix
# ==============================================================================
# Resets synth_1 + impl_1, runs full flow up to write_bitstream.
#
# EXECUTION:
#   "C:/Xilinx/2025.1/Vivado/bin/vivado.bat" -mode batch \
#     -source verilog_ML_KEM/scripts/AXI/rebuild_bitstream.tcl \
#     -tclargs D:/HCMUT/Year_4/252/CA/Vivado/verilog_ML_KEM/verilog_ML_KEM.xpr
# ==============================================================================

if {[llength $argv] < 1} {
    puts "ERROR: Missing project path"
    exit 1
}

set xpr_path [file normalize [lindex $argv 0]]
open_project $xpr_path

# CRITICAL: ensure top is the BD wrapper (not standalone ml_kem_top, which
# has 268 IO ports and fails at place_design). Some prior runs may have
# left top set to ml_kem_top via strategy reset.
set_property top ml_kem_bd_wrapper [current_fileset]
update_compile_order -fileset sources_1
puts "INFO: top fileset: [get_property top [current_fileset]]"

# Area-optimized synth strategy (LUT minimization). WNS budget is generous
# (~2-3 ns at 100 MHz), so we trade timing slack for fewer LUTs.
set_property STRATEGY "Flow_AreaOptimized_high" [get_runs synth_1]

# Force re-synth (RTL changed)
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

# Verify the stage_d1_reg fix took effect.
# Note: pattern dropped the leading `u_` so it matches both the legacy
# per-module instance (`u_inv_ntt/stage_d1_reg*`) and the Step 3.1 lifted
# shared instance (`u_shared_inv_ntt/stage_d1_reg*`). Either form indicates
# dont_touch is preserving the pipeline registers through impl.
open_run impl_1
set survivors [get_cells -hier -filter {NAME =~ *inv_ntt*stage_d1_reg*}]
puts "INFO: surviving stage_d1 registers: [llength $survivors]"
foreach c $survivors {
    puts "  - $c"
}
if {[llength $survivors] == 0} {
    puts "WARNING: stage_d1_reg STILL absent after dont_touch fix. Investigate."
} else {
    puts "PASS: stage_d1_reg preserved through synth+impl"
}

# Quick timing check
set wns [get_property SLACK [get_timing_paths -max_paths 1 -delay_type max]]
puts "INFO: WNS = $wns ns"

# Locate output files
set bit_path [glob -nocomplain [file join [get_property DIRECTORY [current_project]] "*.runs/impl_1/*.bit"]]
set hwh_path [glob -nocomplain [file join [get_property DIRECTORY [current_project]] "*.gen/sources_1/bd/*/hw_handoff/*.hwh"]]
puts "INFO: bitstream -> $bit_path"
puts "INFO: hardware handoff -> $hwh_path"

close_project
exit 0
