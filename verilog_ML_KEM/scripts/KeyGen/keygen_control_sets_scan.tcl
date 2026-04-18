if {[llength $argv] < 1} {
    puts "ERROR: Missing project path argument"
    puts "Usage: vivado -mode batch -source keygen_control_sets_scan.tcl -tclargs <xpr_path> [impl_run]"
    exit 1
}

set xpr_path [file normalize [lindex $argv 0]]
set impl_run [expr {[llength $argv] >= 2 ? [lindex $argv 1] : "impl_1"}]

set script_dir [file dirname [file normalize [info script]]]
set ts [clock format [clock seconds] -format "%Y%m%d_%H%M%S"]
set out_dir [file normalize [file join $script_dir "keygen_metrics" "control_sets_$ts"]]
file mkdir $out_dir
cd $out_dir

puts "INFO: output directory: $out_dir"

open_project $xpr_path

set impl_obj [get_runs -quiet $impl_run]
if {[llength $impl_obj] == 0} {
    puts "ERROR: Cannot find implementation run '$impl_run'"
    close_project
    exit 2
}

open_run $impl_run

set rpt_cs [file join $out_dir "control_sets_impl.rpt"]
set rpt_hier [file join $out_dir "util_hier_impl.rpt"]
set rpt_sum [file join $out_dir "timing_impl_summary.rpt"]

report_control_sets -verbose -file $rpt_cs
report_utilization -hierarchical -file $rpt_hier
report_timing_summary -delay_type min_max -report_unconstrained -max_paths 10 -file $rpt_sum

puts "PASS: reports generated"
puts "INFO: control sets report: $rpt_cs"

close_project
exit 0
