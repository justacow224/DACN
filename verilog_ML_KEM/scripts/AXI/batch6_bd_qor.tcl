# ==============================================================================
# Batch 6 — BD wrapper synth + impl QoR (Gate 3 signoff)
# ==============================================================================
# Usage (inside the Vivado project that owns the BD design):
#   source verilog_ML_KEM/scripts/AXI/batch6_bd_qor.tcl
#
# Optional override (if BD top differs from default `ml_kem_bd_wrapper`):
#   set ::env(BD_TOP) my_other_wrapper
#   source verilog_ML_KEM/scripts/AXI/batch6_bd_qor.tcl
#
# Pre-requisites:
#  - Project is open and contains the block design with ml_kem_top as IP.
#  - Phase C v6 RTL is in fileset (kpke_encrypt.v / ml_kem_keygen.v /
#    ml_kem_encaps.v / ml_kem_decaps.v / kpke_core.v / ml_kem_top.v all
#    updated). If you re-built BD before v6, run `report_ip_status` and
#    `upgrade_ip [get_ips]` first to refresh ml_kem_top IP packaging.
#  - constrs_1 contains ml_kem_kr260.xdc.
# ==============================================================================

if {[llength [get_projects]] == 0} {
    error "No open Vivado project. Open the BD project first."
}

if {[llength [get_runs synth_1]] == 0} {
    error "Run synth_1 not found in current project."
}

if {[llength [get_runs impl_1]] == 0} {
    error "Run impl_1 not found in current project."
}

# Allow env override; default matches the existing BD wrapper from v3.
set bd_top "ml_kem_bd_wrapper"
if {[info exists ::env(BD_TOP)] && [string length $::env(BD_TOP)] > 0} {
    set bd_top $::env(BD_TOP)
    puts "INFO: BD_TOP override = $bd_top"
}

# Make sure Phase C source is in fileset (defensive — same as OOC helper).
set script_dir [file dirname [file normalize [info script]]]
set src_root [file normalize [file join $script_dir ".." ".."]]
foreach f {kpke_core.v} {
    set abs_f [file normalize [file join $src_root "sources_1" "new" $f]]
    if {[file exists $abs_f] && ([llength [get_files -quiet $abs_f]] == 0)} {
        puts "INFO: Adding missing source file: $abs_f"
        add_files -norecurse $abs_f
        update_compile_order -fileset sources_1
    }
}

# Switch synth_1 top to the BD wrapper (NOT ml_kem_top — that would expose
# AXI on package pins and DRC-fail).
if {[catch {set_property top $bd_top [current_fileset]} err]} {
    puts "WARNING: could not set top via current_fileset: $err"
    set_property top $bd_top [get_filesets sources_1]
}

# Make sure synth is NOT in OOC mode (BD impl is full design context).
set synth_run [get_runs synth_1]
set run_props [list_property $synth_run]
if {[lsearch -exact $run_props "STEPS.SYNTH_DESIGN.ARGS.MODE"] >= 0} {
    set_property -name {STEPS.SYNTH_DESIGN.ARGS.MODE} -value {default} -objects $synth_run
} elseif {[lsearch -exact $run_props "STEPS.SYNTH_DESIGN.ARGS.MORE_OPTIONS"] >= 0} {
    set_property -name {STEPS.SYNTH_DESIGN.ARGS.MORE_OPTIONS} -value {} -objects $synth_run
} elseif {[lsearch -exact $run_props "STEPS.SYNTH_DESIGN.ARGS.MORE OPTIONS"] >= 0} {
    set_property -name {STEPS.SYNTH_DESIGN.ARGS.MORE OPTIONS} -value {} -objects $synth_run
}

set proj_dir [get_property DIRECTORY [current_project]]
set proj_name [get_property NAME [current_project]]
set runs_dir [file normalize [file join $proj_dir "${proj_name}.runs"]]
file mkdir [file join $runs_dir "synth_1"]
file mkdir [file join $runs_dir "impl_1"]

catch {close_design}
reset_run synth_1
set_property strategy {Vivado Synthesis Defaults} $synth_run

puts "INFO: Launching BD synth (top=$bd_top, default mode)..."
launch_runs synth_1 -jobs 8
wait_on_run synth_1

if {[get_property PROGRESS [get_runs synth_1]] != "100%"} {
    error "synth_1 did not complete (progress = [get_property PROGRESS [get_runs synth_1]])."
}

open_run synth_1
report_utilization -file [file join $runs_dir "synth_1" "${bd_top}_utilization_synth.rpt"]
report_utilization -hierarchical -hierarchical_depth 4 \
    -file [file join $runs_dir "synth_1" "${bd_top}_utilization_synth_hier.rpt"]
report_timing_summary -file [file join $runs_dir "synth_1" "${bd_top}_timing_synth.rpt"]
puts "INFO: Synth done. Reports under $runs_dir/synth_1/"

reset_run impl_1
puts "INFO: Launching BD impl (route_design)..."
launch_runs impl_1 -to_step route_design -jobs 8
wait_on_run impl_1

if {[get_property PROGRESS [get_runs impl_1]] != "100%"} {
    error "impl_1 did not complete (progress = [get_property PROGRESS [get_runs impl_1]])."
}

open_run impl_1
report_utilization -file [file join $runs_dir "impl_1" "${bd_top}_utilization_impl.rpt"]
report_timing_summary -file [file join $runs_dir "impl_1" "${bd_top}_timing_impl.rpt"]
report_drc -file [file join $runs_dir "impl_1" "${bd_top}_drc_impl.rpt"]

# Quick stdout summary so user can decide signoff at a glance.
set wns_post [get_property STATS.WNS [get_runs impl_1]]
set whs_post [get_property STATS.WHS [get_runs impl_1]]
set tns_post [get_property STATS.TNS [get_runs impl_1]]
puts "==================================================="
puts "BD signoff snapshot — $bd_top"
puts "  WNS post-route: $wns_post ns"
puts "  WHS post-route: $whs_post ns"
puts "  TNS post-route: $tns_post ns"
puts "==================================================="

if {$wns_post < 0} {
    puts "WARNING: WNS < 0 — timing not closed. Investigate before generating bitstream."
} else {
    puts "INFO: WNS >= 0. Proceed to write_bitstream when ready:"
    puts "  launch_runs impl_1 -to_step write_bitstream -jobs 8"
    puts "  wait_on_run impl_1"
}

puts "INFO: All reports written to $runs_dir"
