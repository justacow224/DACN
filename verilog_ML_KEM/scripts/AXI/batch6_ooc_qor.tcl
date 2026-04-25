# Batch 6 - OOC synth helper
# Usage: open Vivado project, then:
#   source verilog_ML_KEM/scripts/AXI/batch6_ooc_qor.tcl

if {[llength [get_projects]] == 0} {
    error "No open Vivado project. Open project first."
}

if {[llength [get_runs synth_1]] == 0} {
    error "Run synth_1 not found in current project."
}

set proj_dir [get_property DIRECTORY [current_project]]
set proj_name [get_property NAME [current_project]]
set runs_dir [file normalize [file join $proj_dir "${proj_name}.runs"]]
set synth_report_dir [file join $runs_dir "synth_1"]
file mkdir $synth_report_dir

# Gate 2 introduced kpke_core.v; add automatically if missing in project fileset.
set script_dir [file dirname [file normalize [info script]]]
set src_root [file normalize [file join $script_dir ".." ".."]]
set kpke_core_file [file normalize [file join $src_root "sources_1" "new" "kpke_core.v"]]
if {[file exists $kpke_core_file] && ([llength [get_files -quiet $kpke_core_file]] == 0)} {
    puts "INFO: Adding missing source file: $kpke_core_file"
    add_files -norecurse $kpke_core_file
    update_compile_order -fileset sources_1
}

set synth_run [get_runs synth_1]
catch {close_design}
reset_run synth_1
set_property strategy {Vivado Synthesis Defaults} $synth_run

# Vivado version compatibility: choose existing OOC argument property.
set run_props [list_property $synth_run]
if {[lsearch -exact $run_props "STEPS.SYNTH_DESIGN.ARGS.MODE"] >= 0} {
    set_property -name {STEPS.SYNTH_DESIGN.ARGS.MODE} -value {out_of_context} -objects $synth_run
} elseif {[lsearch -exact $run_props "STEPS.SYNTH_DESIGN.ARGS.MORE_OPTIONS"] >= 0} {
    set_property -name {STEPS.SYNTH_DESIGN.ARGS.MORE_OPTIONS} -value {-mode out_of_context} -objects $synth_run
} elseif {[lsearch -exact $run_props "STEPS.SYNTH_DESIGN.ARGS.MORE OPTIONS"] >= 0} {
    set_property -name {STEPS.SYNTH_DESIGN.ARGS.MORE OPTIONS} -value {-mode out_of_context} -objects $synth_run
} else {
    puts "ERROR: Cannot find OOC synth argument property on synth_1."
    puts "INFO: Available SYNTH args properties:"
    foreach p $run_props {
        if {[string match "STEPS.SYNTH_DESIGN.ARGS.*" $p]} {
            puts "  $p"
        }
    }
    error "Unsupported Vivado property schema for out_of_context run setup."
}

launch_runs synth_1 -jobs 8
wait_on_run synth_1

open_run synth_1
report_utilization -file [file join $synth_report_dir "ml_kem_top_utilization_ooc.rpt"]
report_utilization -hierarchical -hierarchical_depth 4 -file [file join $synth_report_dir "ml_kem_top_utilization_ooc_hier.rpt"]
if {[llength [get_clocks -quiet]] == 0} {
    create_clock -period 10.000 -name ooc_clk [get_ports clk]
    puts "INFO: Added OOC placeholder clock (100 MHz)"
}
report_timing_summary -file [file join $synth_report_dir "ml_kem_top_timing_ooc.rpt"]

puts "INFO: OOC synthesis done. Reports written to $synth_report_dir"
