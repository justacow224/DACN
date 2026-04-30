# ==============================================================================
# R-new-A Phase A: tb_keccak_f1600_core lane-interface regression
# ==============================================================================
# Verifies that the new xor_lane_we / xor_lane_addr / xor_lane_data / lane_dout
# interface produces semantically identical results to the byte path on a
# Keccak-f[1600] permutation. Also re-runs the original 5 byte/state_in
# testcases to ensure the legacy path is unbroken.
#
# CLEANUP (if locked): taskkill /F /IM xsimk.exe /T & taskkill /F /IM xsim.exe /T & taskkill /F /IM vivado.exe /T
#
# EXECUTION (CMD):
# cd /d D:\HCMUT\Year_4\252\CA\Source\DACN && "C:\Xilinx\2025.1\Vivado\bin\vivado.bat" -mode batch -source verilog_ML_KEM/scripts/Keccak/sim_core_phase_a.tcl -tclargs D:/HCMUT/Year_4/252/CA/Vivado/verilog_ML_KEM/verilog_ML_KEM.xpr
# ==============================================================================

if {[llength $argv] < 1} {
    puts "ERROR: Missing project path argument"
    puts "Usage: vivado -mode batch -source sim_core_phase_a.tcl -tclargs <xpr_path>"
    exit 1
}

# 1. Setup paths and isolation
set xpr_path [file normalize [lindex $argv 0]]
set script_dir [file dirname [file normalize [info script]]]
set base_out_dir [file join $script_dir "keccak_metrics"]
set ts [clock format [clock seconds] -format "%Y%m%d_%H%M%S"]
set run_dir [file join $base_out_dir "sim_core_phase_a_$ts"]

file mkdir $run_dir
cd $run_dir
puts "INFO: Running simulation in isolated directory: $run_dir"

# 2. Open project and harden simulation
open_project $xpr_path

if {[llength [current_sim -quiet]] > 0} {
    puts "INFO: Closing previous simulation session..."
    close_sim -force
}

set_property top tb_keccak_f1600_core [get_filesets sim_1]
update_compile_order -fileset sim_1
set_property xsim.simulate.runtime all [get_filesets sim_1]

# Workaround for Windows env where `.` is not in PATH (NoDefaultCurrentDirectoryInExePath
# in effect). Vivado's launch_simulation spawns `compile.bat` (no path prefix) from the
# xsim run dir; with `.` excluded from PATH, CreateProcess can't resolve it. Prepend
# the xsim dir to PATH so the bat is found by name.
set xsim_run_dir [file normalize [file join [get_property DIRECTORY [current_project]] "[get_property NAME [current_project]].sim" "sim_1" "behav" "xsim"]]
if {[info exists ::env(PATH)]} {
    set ::env(PATH) "$xsim_run_dir;$::env(PATH)"
} else {
    set ::env(PATH) $xsim_run_dir
}
puts "INFO: Prepended xsim run dir to PATH for compile.bat resolution: $xsim_run_dir"

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
    puts "ERROR: launch_simulation failed after retries."
    if {[string match "*\[VRFC*" $launch_err] || [string match "*\[XSIM*" $launch_err]} {
        puts "HINT: This looks like a Compilation (*VRFC*) or Elaboration (*XSIM*) error."
        puts "ACTION: Check the detailed log above for syntax errors in Phase A changes."
    } else {
        puts "HINT: Ensure no other Vivado instance is locking the simulation files."
    }
    puts "DETAIL: $launch_err"
    close_project
    exit 5
}

# 3. Run and analyze
set xsim_log [file normalize [file join [get_property DIRECTORY [current_project]] "[get_property NAME [current_project]].sim" "sim_1" "behav" "xsim" "simulate.log"]]
catch {close_sim -force}

if {![file exists $xsim_log]} {
    puts "ERROR: simulate.log not found at $xsim_log"
    close_project
    exit 2
}

file copy -force $xsim_log [file join $run_dir "phase_a_simulate.log"]

set fp [open [file join $run_dir "phase_a_simulate.log"] r]
set log_txt [read $fp]
close $fp

# Must-have markers for Phase A signoff:
#  - all 5 legacy byte/state_in testcases pass
#  - the new Phase A lane-mode testcase passes
set must_have [list \
    "ALL 5 TESTCASES PASSED FLAWLESSLY" \
    "R-new-A Phase A LANE-MODE TESTCASE PASSED" \
    "Phase A lane interface OK"]

set must_not_have [list \
    "\[FAILED\]" \
    "Output mismatch" \
    "lane_dout mismatch" \
    "wrong state_out" \
    "TIMEOUT" \
    "\$stop called"]

foreach p $must_have {
    if {[string first $p $log_txt] < 0} {
        puts "ERROR: Phase A TB missing PASS marker: $p"
        close_project
        exit 3
    }
}

foreach p $must_not_have {
    if {[string first $p $log_txt] >= 0} {
        puts "ERROR: Phase A TB found failure marker: $p"
        close_project
        exit 4
    }
}

puts "PASS: R-new-A Phase A regression gate passed"
puts "INFO: All outputs located in $run_dir"
close_project
exit 0
