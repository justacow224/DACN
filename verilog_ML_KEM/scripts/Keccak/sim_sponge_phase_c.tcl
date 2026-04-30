# ==============================================================================
# R-new-A Phase C: tb_keccak_sponge_top lane-squeeze regression
# ==============================================================================
# Verifies that the new lane-mode squeeze path produces byte-for-byte identical
# Keccak output as the byte-mode path. Re-runs all 7 prior testcases plus
# adds testcase 8: 200-byte SHAKE128 squeezed via lane_dout (25 lanes), each
# lane packed {byte[7..0]} from exp_multi_squeeze.
#
# CLEANUP (if locked): taskkill /F /IM xsimk.exe /T & taskkill /F /IM xsim.exe /T & taskkill /F /IM vivado.exe /T
#
# EXECUTION (CMD):
# cd /d D:\HCMUT\Year_4\252\CA\Source\DACN && "C:\Xilinx\2025.1\Vivado\bin\vivado.bat" -mode batch -source verilog_ML_KEM/scripts/Keccak/sim_sponge_phase_c.tcl -tclargs D:/HCMUT/Year_4/252/CA/Vivado/verilog_ML_KEM/verilog_ML_KEM.xpr
# ==============================================================================

if {[llength $argv] < 1} {
    puts "ERROR: Missing project path argument"
    puts "Usage: vivado -mode batch -source sim_sponge_phase_c.tcl -tclargs <xpr_path>"
    exit 1
}

# 1. Setup paths and isolation
set xpr_path [file normalize [lindex $argv 0]]
set script_dir [file dirname [file normalize [info script]]]
set base_out_dir [file join $script_dir "keccak_metrics"]
set ts [clock format [clock seconds] -format "%Y%m%d_%H%M%S"]
set run_dir [file join $base_out_dir "sim_sponge_phase_c_$ts"]

file mkdir $run_dir
cd $run_dir
puts "INFO: Running simulation in isolated directory: $run_dir"

# 2. Open project and harden simulation
open_project $xpr_path

if {[llength [current_sim -quiet]] > 0} {
    puts "INFO: Closing previous simulation session..."
    close_sim -force
}

set_property top tb_keccak_sponge_top [get_filesets sim_1]
update_compile_order -fileset sim_1
set_property xsim.simulate.runtime all [get_filesets sim_1]

# Workaround for Windows env where `.` is not in PATH (NoDefaultCurrentDirectoryInExePath)
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

file copy -force $xsim_log [file join $run_dir "phase_c_simulate.log"]

set fp [open [file join $run_dir "phase_c_simulate.log"] r]
set log_txt [read $fp]
close $fp

set must_have [list \
    "SHAKE128 PASSED" \
    "SHAKE256 PASSED" \
    "SHA3-256 PASSED" \
    "SHA3-512 PASSED" \
    "MULTI-BLOCK ABSORB PASSED" \
    "MULTI-BLOCK SQUEEZE PASSED" \
    "R-new-A Phase B LANE ABSORB PASSED" \
    "R-new-A Phase C LANE SQUEEZE PASSED" \
    "ALL 8 TESTCASES PASSED FLAWLESSLY"]

set must_not_have [list \
    "\[ERROR\]" \
    "TIMEOUT" \
    "\$stop called"]

foreach p $must_have {
    if {[string first $p $log_txt] < 0} {
        puts "ERROR: Phase C TB missing PASS marker: $p"
        close_project
        exit 3
    }
}

foreach p $must_not_have {
    if {[string first $p $log_txt] >= 0} {
        puts "ERROR: Phase C TB found failure marker: $p"
        close_project
        exit 4
    }
}

puts "PASS: R-new-A Phase C regression gate passed"
puts "INFO: All outputs located in $run_dir"
close_project
exit 0
