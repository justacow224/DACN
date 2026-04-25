# Batch 6 - normal synth + impl QoR helper
# Usage: open Vivado project, then:
#   source verilog_ML_KEM/scripts/AXI/batch6_impl_qor.tcl

if {[llength [get_projects]] == 0} {
    error "No open Vivado project. Open project first."
}

if {[llength [get_runs synth_1]] == 0} {
    error "Run synth_1 not found in current project."
}

if {[llength [get_runs impl_1]] == 0} {
    error "Run impl_1 not found in current project."
}

set proj_dir [get_property DIRECTORY [current_project]]
set proj_name [get_property NAME [current_project]]
set runs_dir [file normalize [file join $proj_dir "${proj_name}.runs"]]
set synth_report_dir [file join $runs_dir "synth_1"]
set impl_report_dir [file join $runs_dir "impl_1"]
file mkdir $synth_report_dir
file mkdir $impl_report_dir

# Gate 2 introduced kpke_core.v; add automatically if missing in project fileset.
set script_dir [file dirname [file normalize [info script]]]
set src_root [file normalize [file join $script_dir ".." ".."]]
set kpke_core_file [file normalize [file join $src_root "sources_1" "new" "kpke_core.v"]]
if {[file exists $kpke_core_file] && ([llength [get_files -quiet $kpke_core_file]] == 0)} {
    puts "INFO: Adding missing source file: $kpke_core_file"
    add_files -norecurse $kpke_core_file
    update_compile_order -fileset sources_1
}

catch {close_design}
reset_run synth_1
set synth_run [get_runs synth_1]
set_property strategy {Vivado Synthesis Defaults} $synth_run

# Vivado version compatibility: clear any previous OOC synth argument.
set run_props [list_property $synth_run]
if {[lsearch -exact $run_props "STEPS.SYNTH_DESIGN.ARGS.MODE"] >= 0} {
    set_property -name {STEPS.SYNTH_DESIGN.ARGS.MODE} -value {default} -objects $synth_run
}
if {[lsearch -exact $run_props "STEPS.SYNTH_DESIGN.ARGS.MORE_OPTIONS"] >= 0} {
    set_property -name {STEPS.SYNTH_DESIGN.ARGS.MORE_OPTIONS} -value {} -objects $synth_run
}
if {[lsearch -exact $run_props "STEPS.SYNTH_DESIGN.ARGS.MORE OPTIONS"] >= 0} {
    set_property -name {STEPS.SYNTH_DESIGN.ARGS.MORE OPTIONS} -value {} -objects $synth_run
}
launch_runs synth_1 -jobs 8
wait_on_run synth_1

open_run synth_1
report_utilization -file [file join $synth_report_dir "ml_kem_top_utilization_synth_latest.rpt"]
report_timing_summary -file [file join $synth_report_dir "ml_kem_top_timing_synth_latest.rpt"]

catch {close_design}
reset_run impl_1
launch_runs impl_1 -to_step route_design -jobs 8
wait_on_run impl_1

open_run impl_1
report_utilization -file [file join $impl_report_dir "ml_kem_top_utilization_impl_latest.rpt"]
report_timing_summary -file [file join $impl_report_dir "ml_kem_top_timing_impl_latest.rpt"]

puts "INFO: Normal synth+impl done. Reports written to $synth_report_dir and $impl_report_dir."
