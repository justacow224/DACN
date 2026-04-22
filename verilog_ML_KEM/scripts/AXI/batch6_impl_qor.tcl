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

reset_run synth_1
set_property strategy {Vivado Synthesis Defaults} [get_runs synth_1]
set_property STEPS.SYNTH_DESIGN.ARGS.MORE_OPTIONS {} [get_runs synth_1]
launch_runs synth_1 -jobs 8
wait_on_run synth_1

open_run synth_1
report_utilization -file ./verilog_ML_KEM.runs/synth_1/ml_kem_top_utilization_synth_latest.rpt
report_timing_summary -file ./verilog_ML_KEM.runs/synth_1/ml_kem_top_timing_synth_latest.rpt

reset_run impl_1
launch_runs impl_1 -to_step route_design -jobs 8
wait_on_run impl_1

open_run impl_1
report_utilization -file ./verilog_ML_KEM.runs/impl_1/ml_kem_top_utilization_impl_latest.rpt
report_timing_summary -file ./verilog_ML_KEM.runs/impl_1/ml_kem_top_timing_impl_latest.rpt

puts "INFO: Normal synth+impl done. Reports written to verilog_ML_KEM.runs/synth_1 and impl_1."
