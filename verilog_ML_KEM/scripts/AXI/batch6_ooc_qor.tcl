# Batch 6 - OOC synth helper
# Usage: open Vivado project, then:
#   source verilog_ML_KEM/scripts/AXI/batch6_ooc_qor.tcl

if {[llength [get_projects]] == 0} {
    error "No open Vivado project. Open project first."
}

if {[llength [get_runs synth_1]] == 0} {
    error "Run synth_1 not found in current project."
}

set synth_run [get_runs synth_1]
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
report_utilization -file ./verilog_ML_KEM.runs/synth_1/ml_kem_top_utilization_ooc.rpt
report_utilization -hierarchical -hierarchical_depth 4 -file ./verilog_ML_KEM.runs/synth_1/ml_kem_top_utilization_ooc_hier.rpt
report_timing_summary -file ./verilog_ML_KEM.runs/synth_1/ml_kem_top_timing_ooc.rpt

puts "INFO: OOC synthesis done. Reports written to verilog_ML_KEM.runs/synth_1/"
