# ==============================================================================
# KeyGen Impl-Only Flow (Synthesis + Implementation, no simulation)
# ==============================================================================
# CLEANUP (if locked): taskkill /F /IM xsimk.exe /T; taskkill /F /IM xsim.exe /T; taskkill /F /IM vivado.bat /T; taskkill /F /IM vivado.exe /T
#
# EXECUTION (CMD): 
# cd /d D:\HCMUT\Year_4\252\CA\Source\DACN && "C:\Xilinx\2025.1\Vivado\bin\vivado.bat" -mode batch -source verilog_ML_KEM/scripts/KeyGen/keygen_impl_only.tcl -tclargs D:/HCMUT/Year_4/252/CA/Vivado/verilog_ML_KEM/verilog_ML_KEM.xpr 8
# ==============================================================================

proc _fail {msg code} {
    puts "ERROR: $msg"
    if {[string length [current_project -quiet]] > 0} {
        catch {close_project}
    }
    exit $code
}

proc _slack_to_double {v} {
    if {[string equal -nocase $v "INF"] || [string equal -nocase $v "+INF"]} { return 1.0e9 }
    if {[string equal -nocase $v "-INF"]} { return -1.0e9 }
    return [expr {double($v)}]
}

proc _ensure_keygen_wrapper_xdc {script_dir} {
    set xdc_name "ml_kem_keygen_io_wrapper.xdc"
    set xdc_path [file normalize [file join $script_dir ".." ".." "constrs_1" "new" $xdc_name]]
    if {![file exists $xdc_path]} {
        _fail "Missing keygen wrapper XDC: $xdc_path" 12
    }

    set xdc_obj [get_files -quiet -of_objects [get_filesets constrs_1] "*$xdc_name"]
    if {[llength $xdc_obj] == 0} {
        puts "INFO: Adding constraints file to constrs_1: $xdc_path"
        add_files -fileset constrs_1 $xdc_path
        set xdc_obj [get_files -quiet -of_objects [get_filesets constrs_1] "*$xdc_name"]
    } else {
        puts "INFO: Reusing existing constraints file in constrs_1: $xdc_name"
    }

    if {[llength $xdc_obj] == 0} {
        _fail "Failed to attach keygen wrapper XDC to constrs_1" 13
    }

    set_property USED_IN_SYNTHESIS true $xdc_obj
    set_property USED_IN_IMPLEMENTATION true $xdc_obj
    set_property IS_ENABLED true $xdc_obj
    update_compile_order -fileset constrs_1
}

if {[llength $argv] < 1} {
    puts "ERROR: Missing project path argument"
    puts "Usage: vivado -mode batch -source keygen_impl_only.tcl -tclargs <xpr_path> [jobs] [synth_run] [impl_run] [control_set_opt_threshold]"
    exit 1
}

set xpr_path  [file normalize [lindex $argv 0]]
set jobs      [expr {[llength $argv] >= 2 ? [lindex $argv 1] : 8}]
set synth_run [expr {[llength $argv] >= 3 ? [lindex $argv 2] : "synth_1"}]
set impl_run  [expr {[llength $argv] >= 4 ? [lindex $argv 3] : "impl_1"}]
set cs_thresh [expr {[llength $argv] >= 5 ? [lindex $argv 4] : 4}]

set script_dir [file dirname [file normalize [info script]]]
set ts [clock format [clock seconds] -format "%Y%m%d_%H%M%S"]
set out_dir [file normalize [file join $script_dir "keygen_metrics" "impl_only_$ts"]]
file mkdir $out_dir
cd $out_dir
puts "INFO: Running impl-only flow in isolated directory: $out_dir"

open_project $xpr_path
_ensure_keygen_wrapper_xdc $script_dir

set synth_obj [get_runs -quiet $synth_run]
set impl_obj  [get_runs -quiet $impl_run]
if {[llength $synth_obj] == 0} { _fail "Cannot find synthesis run '$synth_run'" 30 }
if {[llength $impl_obj]  == 0} { _fail "Cannot find implementation run '$impl_run'" 31 }

puts "INFO: Setting synthesis top module to ml_kem_keygen_io_wrapper"
set_property top ml_kem_keygen_io_wrapper [current_fileset]
update_compile_order -fileset sources_1

set_property STEPS.SYNTH_DESIGN.ARGS.INCREMENTAL_MODE off $synth_obj
set_property STEPS.SYNTH_DESIGN.ARGS.CONTROL_SET_OPT_THRESHOLD $cs_thresh $synth_obj
puts "INFO: CONTROL_SET_OPT_THRESHOLD=$cs_thresh"

catch {reset_run $impl_run}
catch {reset_run $synth_run}

puts "INFO: Launching synthesis run '$synth_run' (jobs=$jobs)"
launch_runs $synth_run -jobs $jobs
wait_on_run $synth_run
open_run $synth_run

report_utilization -hierarchical -file [file join $out_dir util_hier_synth.rpt]
report_utilization -file [file join $out_dir util_flat_synth.rpt]
report_timing_summary -file [file join $out_dir timing_synth.rpt]
report_ram_utilization -file [file join $out_dir ram_synth.rpt]
report_methodology -file [file join $out_dir methodology_synth.rpt]

puts "INFO: Launching implementation run '$impl_run' to route_design (jobs=$jobs)"
launch_runs $impl_run -to_step route_design -jobs $jobs
wait_on_run $impl_run
open_run $impl_run

report_utilization -hierarchical -file [file join $out_dir util_hier_impl.rpt]
report_utilization -file [file join $out_dir util_flat_impl.rpt]
report_control_sets -verbose -file [file join $out_dir control_sets_impl.rpt]
report_timing_summary -delay_type min_max -report_unconstrained -max_paths 20 -file [file join $out_dir timing_impl.rpt]
report_methodology -file [file join $out_dir methodology_impl.rpt]

set setup_paths [get_timing_paths -max_paths 1 -setup]
set hold_paths  [get_timing_paths -max_paths 1 -hold]
if {[llength $setup_paths] == 0 || [llength $hold_paths] == 0} {
    _fail "Cannot query setup/hold timing paths" 32
}

set wns_raw [get_property SLACK [lindex $setup_paths 0]]
set whs_raw [get_property SLACK [lindex $hold_paths 0]]
set wns [_slack_to_double $wns_raw]
set whs [_slack_to_double $whs_raw]
puts [format "INFO: Timing summary (impl): WNS=%s WHS=%s" $wns_raw $whs_raw]

if {$wns < 0.0} { _fail "Implementation timing failed: WNS ($wns_raw)" 33 }
if {$whs < 0.0} { _fail "Implementation timing failed: WHS ($whs_raw)" 34 }

puts "PASS: keygen impl-only flow completed. Outputs in $out_dir"
close_project
exit 0
