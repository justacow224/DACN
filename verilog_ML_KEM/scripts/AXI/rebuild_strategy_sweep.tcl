# ==============================================================================
# Strategy sweep — try multiple synth strategies to bisect optimization bug
# ==============================================================================
# Builds the same RTL with 4 different Vivado synth strategies. If one passes
# KAT on board where the default fails, we know which optimization combo to
# avoid. Output:
#   verilog_ML_KEM/bitstream/strategies/<strategy>/ml_kem_bd.{bit,hwh}
#   verilog_ML_KEM/bitstream/strategies/<strategy>/synth_1.log (warning summary)
#
# Total runtime: ~4 x 25 min = ~1.5-2h.
#
# EXECUTION:
#   "C:/Xilinx/2025.1/Vivado/bin/vivado.bat" -mode batch \
#     -source verilog_ML_KEM/scripts/AXI/rebuild_strategy_sweep.tcl \
#     -tclargs D:/HCMUT/Year_4/252/CA/Vivado/verilog_ML_KEM/verilog_ML_KEM.xpr
# ==============================================================================

if {[llength $argv] < 1} {
    puts "ERROR: Missing project path"
    exit 1
}

set xpr_path [file normalize [lindex $argv 0]]
set repo_root [file normalize [file join [file dirname [info script]] ".." ".." ".."]]
set out_root  [file join $repo_root "verilog_ML_KEM" "bitstream" "strategies"]

# 4 strategies to try, in order of "most likely to differ from default" first.
set strategies [list \
    "Flow_RuntimeOptimized" \
    "Flow_AreaOptimized_high" \
    "Flow_PerfOptimized_high" \
    "Flow_AlternateRoutability" \
]

open_project $xpr_path
set_property top ml_kem_bd_wrapper [current_fileset]
update_compile_order -fileset sources_1
puts "INFO: top fileset: [get_property top [current_fileset]]"

set src_bit_path  "[get_property DIRECTORY [current_project]]/[get_property NAME [current_project]].runs/impl_1/ml_kem_bd_wrapper.bit"
set src_hwh_path  "[get_property DIRECTORY [current_project]]/[get_property NAME [current_project]].gen/sources_1/bd/ml_kem_bd/hw_handoff/ml_kem_bd.hwh"
set synth_log_path "[get_property DIRECTORY [current_project]]/[get_property NAME [current_project]].runs/synth_1/runme.log"

set summary {}

foreach strat $strategies {
    puts ""
    puts "=========================================================="
    puts "STRATEGY: $strat"
    puts "=========================================================="

    set out_dir [file join $out_root $strat]
    file mkdir $out_dir

    # Reset and apply strategy
    set_property STRATEGY $strat [get_runs synth_1]
    # Make sure top stays correct after strategy reset
    set_property top ml_kem_bd_wrapper [current_fileset]

    reset_run synth_1
    if {[catch {launch_runs impl_1 -to_step write_bitstream -jobs 8} err]} {
        puts "ERROR: launch_runs failed for $strat: $err"
        lappend summary "$strat: LAUNCH_FAILED"
        continue
    }
    if {[catch {wait_on_run impl_1} err]} {
        puts "ERROR: wait_on_run failed for $strat: $err"
        lappend summary "$strat: BUILD_FAILED"
        # Still try to copy whatever artifacts exist
        if {[file exists $synth_log_path]} {
            file copy -force $synth_log_path [file join $out_dir "synth_1.log"]
        }
        continue
    }

    set status [get_property STATUS [get_runs impl_1]]
    if {[string first "write_bitstream Complete" $status] < 0} {
        puts "ERROR: bitstream not generated for $strat. Status: $status"
        lappend summary "$strat: NO_BITSTREAM ($status)"
        if {[file exists $synth_log_path]} {
            file copy -force $synth_log_path [file join $out_dir "synth_1.log"]
        }
        continue
    }

    # Copy artifacts
    file copy -force $src_bit_path [file join $out_dir "ml_kem_bd.bit"]
    file copy -force $src_hwh_path [file join $out_dir "ml_kem_bd.hwh"]
    file copy -force $synth_log_path [file join $out_dir "synth_1.log"]

    # Quick stats
    open_run impl_1 -quiet
    set wns [get_property SLACK [get_timing_paths -max_paths 1 -delay_type max]]
    close_design -quiet

    set warn_count [exec grep -c "Synth 8-7137" [file join $out_dir "synth_1.log"]]

    puts "INFO: $strat -> bit copied. WNS=$wns ns, Synth 8-7137 count=$warn_count"
    lappend summary "$strat: PASS (WNS=$wns, S8-7137=$warn_count)"
}

# Final summary
puts ""
puts "=========================================================="
puts "STRATEGY SWEEP SUMMARY"
puts "=========================================================="
foreach line $summary {
    puts "  $line"
}
puts ""
puts "Bitstreams saved under: $out_root"
puts "Test each on board sequentially:"
puts "  1. Copy ml_kem_bd.bit + ml_kem_bd.hwh from a strategy subdir to board"
puts "  2. Restart Jupyter kernel"
puts "  3. Run KAT debug cell"
puts "  4. If pass, that strategy avoids the bug. Move on."

close_project
exit 0
