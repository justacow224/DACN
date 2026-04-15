# Unified Simulation Script: Wrapper TB
# This script ensures all Vivado clutter is isolated in a timestamped metrics folder.

if {[llength $argv] < 1} {
    puts "ERROR: Missing project path argument"
    puts "Usage: vivado -mode batch -source sim_wrapper.tcl -tclargs <xpr_path> [jobs]"
    exit 1
}

# 1. Setup paths and isolation
set xpr_path [file normalize [lindex $argv 0]]
set script_dir [file dirname [file normalize [info script]]]
set base_out_dir [file join $script_dir "keygen_metrics"]
set ts [clock format [clock seconds] -format "%Y%m%d_%H%M%S"]
set run_dir [file join $base_out_dir "sim_wrapper_$ts"]

file mkdir $run_dir
cd $run_dir
puts "INFO: Running simulation in isolated directory: $run_dir"

# 2. Open project and harden simulation
open_project $xpr_path

# Force close any existing simulation sessions in this project to prevent hangs
if {[llength [current_sim -quiet]] > 0} {
    puts "INFO: Closing previous simulation session..."
    close_sim -force
}

set_property top tb_ml_kem_keygen_wrapper [get_filesets sim_1]
update_compile_order -fileset sim_1

set launched 0
set launch_err ""
for {set t 0} {$t < 5} {incr t} {
    # Attempt to reset simulation if it failed previously
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
    puts "ERROR: launch_simulation failed after retries."
    puts "HINT: Ensure no other Vivado instance is locking the simulation files."
    puts "DETAIL: $launch_err"
    close_project
    exit 5
}

# 3. Run and analyze
catch {run all}
set xsim_log [file normalize [file join [get_property DIRECTORY [current_project]] "[get_property NAME [current_project]].sim" "sim_1" "behav" "xsim" "simulate.log"]]
catch {close_sim -force}

if {![file exists $xsim_log]} {
    puts "ERROR: simulate.log not found at $xsim_log"
    close_project
    exit 2
}

# Copy log to run_dir for record-keeping before closing project
file copy -force $xsim_log [file join $run_dir "wrapper_tb_simulate.log"]

set fp [open [file join $run_dir "wrapper_tb_simulate.log"] r]
set log_txt [read $fp]
close $fp

set must_have [list "ALL WRAPPER KAT PASSED: 100 vectors"]
set must_not_have [list "SK mismatch (wrapper)" "TIMEOUT" "\$stop called"]

foreach p $must_have {
    if {[string first $p $log_txt] < 0} {
        puts "ERROR: wrapper TB missing PASS marker: $p"
        close_project
        exit 3
    }
}

foreach p $must_not_have {
    if {[string first $p $log_txt] >= 0} {
        puts "ERROR: wrapper TB found failure marker: $p"
        close_project
        exit 4
    }
}

puts "PASS: wrapper TB regression gate passed"
puts "INFO: All outputs located in $run_dir"
close_project
exit 0
