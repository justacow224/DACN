# ==============================================================================
# Unified Simulation Script: KeyGen Full Flow (Sim + Synth + Impl)
# ==============================================================================
# CLEANUP (if locked): taskkill /F /IM xsimk.exe /T; taskkill /F /IM xsim.exe /T; taskkill /F /IM vivado.bat /T; taskkill /F /IM vivado.exe /T
#
# EXECUTION (CMD): 
# cd /d D:\HCMUT\Year_4\252\CA\Source\DACN && "C:\Xilinx\2025.1\Vivado\bin\vivado.bat" -mode batch -source verilog_ML_KEM/scripts/KeyGen/keygen_full_flow.tcl -tclargs D:/HCMUT/Year_4/252/CA/Vivado/verilog_ML_KEM/verilog_ML_KEM.xpr 8
# ==============================================================================
# This script ensures all Vivado clutter is isolated in a timestamped metrics folder.

proc _fail {msg code} {
    puts "ERROR: $msg"
    set ::flow_status "FAIL"
    set ::fail_reason $msg
    if {[info exists ::summary_file]} {
        catch {_write_summary}
    }
    if {[string length [current_project -quiet]] > 0} {
        catch {close_project}
    }
    exit $code
}

proc _read_text {path} {
    set fp [open $path r]
    set txt [read $fp]
    close $fp
    return $txt
}

proc _sim_log_path {} {
    set proj_dir  [file normalize [get_property DIRECTORY [current_project]]]
    set proj_name [get_property NAME [current_project]]
    return [file join $proj_dir "${proj_name}.sim" "sim_1" "behav" "xsim" "simulate.log"]
}

proc _check_markers {txt must_have must_not_have label} {
    foreach p $must_have {
        if {[string first $p $txt] < 0} {
            _fail "$label missing PASS marker: $p" 20
        }
    }
    foreach p $must_not_have {
        if {[string first $p $txt] >= 0} {
            _fail "$label found failure marker: $p" 21
        }
    }
}

proc _write_summary {} {
    if {![info exists ::summary_file]} {
        return
    }
    set fp [open $::summary_file w]
    puts $fp "=== KEYGEN FULL FLOW SUMMARY ==="
    puts $fp "timestamp: [clock format [clock seconds] -format {%Y-%m-%d %H:%M:%S}]"
    puts $fp "status: $::flow_status"
    puts $fp "direct_tb: $::direct_status"
    puts $fp "wrapper_tb: $::wrapper_status"
    puts $fp "synthesis: $::synth_status"
    puts $fp "implementation: $::impl_status"
    puts $fp "cycle_mean: $::cycle_mean"
    puts $fp "WNS: $::wns_raw"
    puts $fp "WHS: $::whs_raw"
    if {[string length $::fail_reason] > 0} {
        puts $fp "reason: $::fail_reason"
    }
    close $fp
}

proc _run_tb_gate {top label must_have must_not_have out_dir} {
    puts "INFO: Running $label with top=$top"
    
    # Pre-run cleanup
    if {[llength [current_sim -quiet]] > 0} {
        puts "INFO: Closing previous simulation session for $label..."
        close_sim -force
    }

    set_property top $top [get_filesets sim_1]
    update_compile_order -fileset sim_1
    set_property xsim.simulate.runtime all [get_filesets sim_1]
    
    set launched 0
    set launch_err ""
    for {set t 0} {$t < 5} {incr t} {
        if {$t > 0} {
            puts "RETRY: Resetting simulation state ($t)..."
            reset_simulation -simset sim_1 -mode behavioral
        }
        if {[catch {launch_simulation -simset sim_1 -mode behavioral} launch_err]} {
            after 2000
        } else {
            set launched 1
            break
        }
    }
    if {!$launched} {
        _fail "$label launch_simulation failed. Check for file locks. Detail: $launch_err" 23
    }
    
    puts "TRACE: Resolving log path..."
    set log_path [_sim_log_path]
    puts "TRACE: Log path = $log_path"
    puts "TRACE: Closing sim force..."
    catch {close_sim -force}
    puts "TRACE: Sim closed."

    if {![file exists $log_path]} {
        _fail "$label cannot find simulate.log: $log_path" 22
    }

    puts "TRACE: Reading log..."
    set txt [_read_text $log_path]

    puts "TRACE: Checking markers..."
    _check_markers $txt $must_have $must_not_have $label
    puts "TRACE: Markers checked."

    if {$label eq "direct_tb"} {
        set ::direct_status "PASS"
        if {[regexp {mean[ \t]*=[ \t]*([0-9]+(?:\.[0-9]+)?)} $txt -> m]} {
            set ::cycle_mean $m
        }
    } elseif {$label eq "wrapper_tb"} {
        set ::wrapper_status "PASS"
    }

    puts "TRACE: Copying log..."
    set dst_log [file join $out_dir "${label}_xsim.log"]
    file copy -force $log_path $dst_log
    puts "PASS: $label gate passed"
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
    puts "Usage: vivado -mode batch -source keygen_full_flow.tcl -tclargs <xpr_path> [jobs] [synth_run] [impl_run] [control_set_opt_threshold]"
    exit 1
}

# 1. Setup paths and isolation
set xpr_path  [file normalize [lindex $argv 0]]
set jobs      [expr {[llength $argv] >= 2 ? [lindex $argv 1] : 8}]
set synth_run [expr {[llength $argv] >= 3 ? [lindex $argv 2] : "synth_1"}]
set impl_run  [expr {[llength $argv] >= 4 ? [lindex $argv 3] : "impl_1"}]
# Keep default threshold conservative to avoid LUT blow-up from aggressive
# control-set remapping. Higher values can reduce control-set count but often
# increase LUT usage substantially.
set cs_thresh [expr {[llength $argv] >= 5 ? [lindex $argv 4] : 4}]

set script_dir [file dirname [file normalize [info script]]]
set ts [clock format [clock seconds] -format "%Y%m%d_%H%M%S"]
set out_dir [file normalize [file join $script_dir "keygen_metrics" "full_flow_$ts"]]
file mkdir $out_dir
set summary_file [file join $out_dir "flow_summary.txt"]

# Isolation: switch working directory to metrics folder
cd $out_dir
puts "INFO: Running full flow in isolated directory: $out_dir"

set flow_status   "RUNNING"
set fail_reason   ""
set direct_status "NOT_RUN"
set wrapper_status "NOT_RUN"
set synth_status  "NOT_RUN"
set impl_status   "NOT_RUN"
set cycle_mean    "N/A"
set wns_raw       "N/A"
set whs_raw       "N/A"

# 2. Start Flow
open_project $xpr_path
_ensure_keygen_wrapper_xdc $script_dir

set direct_must_have [list "ALL KAT PASSED: 100 vectors" "Boundary all-zero seeds: PASSED" "Boundary all-FF seeds: PASSED"]
set direct_must_not  [list "PK Mismatch" "SK Mismatch" "HPK stream mismatch" "TIMEOUT" "\$stop called"]
set wrapper_must_have [list "ALL WRAPPER KAT PASSED: 100 vectors"]
set wrapper_must_not  [list "SK mismatch (wrapper)" "TIMEOUT" "\$stop called"]

_run_tb_gate "tb_ml_kem_keygen"         "direct_tb"  $direct_must_have  $direct_must_not  $out_dir
_run_tb_gate "tb_ml_kem_keygen_wrapper" "wrapper_tb" $wrapper_must_have $wrapper_must_not $out_dir

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
set synth_status "PASS"

report_utilization -hierarchical -file [file join $out_dir util_hier_synth.rpt]
report_utilization -file [file join $out_dir util_flat_synth.rpt]
report_timing_summary -file [file join $out_dir timing_synth.rpt]
report_ram_utilization -file [file join $out_dir ram_synth.rpt]
report_methodology -file [file join $out_dir methodology_synth.rpt]

puts "INFO: Launching implementation run '$impl_run' to route_design (jobs=$jobs)"
launch_runs $impl_run -to_step route_design -jobs $jobs
wait_on_run $impl_run
open_run $impl_run
set impl_status "PASS"

report_utilization -hierarchical -file [file join $out_dir util_hier_impl.rpt]
report_utilization -file [file join $out_dir util_flat_impl.rpt]
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

puts [format "INFO: Timing sanity: WNS=%s WHS=%s" $wns_raw $whs_raw]
if {$wns < 0.0} { _fail "Timing failed: WNS ($wns_raw)" 33 }
if {$whs < 0.0} { _fail "Timing failed: WHS ($whs_raw)" 34 }

set flow_status "PASS"
_write_summary
puts "PASS: full flow completed. Outputs in $out_dir"
close_project
exit 0
