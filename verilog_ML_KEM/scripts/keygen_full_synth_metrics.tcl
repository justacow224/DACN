# Full non-incremental synthesis metrics flow for ml_kem_keygen
# Usage:
#   vivado -mode batch -source keygen_full_synth_metrics.tcl -tclargs <xpr_path> [jobs] [run_name]

if {[llength $argv] < 1} {
    puts "ERROR: Missing project path argument"
    puts "Usage: vivado -mode batch -source keygen_full_synth_metrics.tcl -tclargs <xpr_path> [jobs] [run_name]"
    exit 1
}

set xpr_path [lindex $argv 0]
set jobs [expr {[llength $argv] >= 2 ? [lindex $argv 1] : 8}]
set run_name [expr {[llength $argv] >= 3 ? [lindex $argv 2] : "synth_1"}]

set ts [clock format [clock seconds] -format "%Y%m%d_%H%M%S"]
set out_dir [file normalize [file join [pwd] "keygen_metrics_$ts"]]
file mkdir $out_dir

set opened_here 0
if {[string length [current_project -quiet]] == 0} {
    open_project $xpr_path
    set opened_here 1
} else {
    set cur [get_property NAME [current_project]]
    puts "INFO: Using already-open project: $cur"
}


if {[llength $synth_run] == 0} {
    puts "ERROR: Cannot find run '$run_name'"
    if {$opened_here} {
        close_project
    }
    exit 2
}

# Force full non-incremental synthesis
set_property STEPS.SYNTH_DESIGN.ARGS.INCREMENTAL_MODE false $synth_run

puts "INFO: reset_run $run_name"
catch {reset_run $run_name} reset_msg
puts "INFO: reset_run result: $reset_msg"

launch_runs $run_name -jobs $jobs
wait_on_run $run_name
open_run $run_name

report_utilization -hierarchical -file [file join $out_dir util_hier_synth.rpt]
report_utilization -file [file join $out_dir util_flat_synth.rpt]
report_timing_summary -file [file join $out_dir timing_synth.rpt]
report_ram_utilization -file [file join $out_dir ram_synth.rpt]

puts "INFO: metrics written to $out_dir"
if {$opened_here} {
    close_project
}

