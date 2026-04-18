# ==============================================================================
# Unified Simulation Script: Direct TB for K-PKE Decrypt
# ==============================================================================
# CLEANUP (if locked): taskkill /F /IM xsimk.exe /T; taskkill /F /IM xsim.exe /T; taskkill /F /IM vivado.bat /T; taskkill /F /IM vivado.exe /T
#
# EXECUTION (CMD): 
# cd /d D:\HCMUT\Year_4\252\CA\Source\DACN && "C:\Xilinx\2025.1\Vivado\bin\vivado.bat" -mode batch -source verilog_ML_KEM/scripts/Decaps/sim_kpke_decrypt.tcl -tclargs D:/HCMUT/Year_4/252/CA/Vivado/verilog_ML_KEM/verilog_ML_KEM.xpr
# ==============================================================================
# This script ensures all Vivado clutter is isolated in a timestamped metrics folder.

if {[llength $argv] < 1} {
    puts "ERROR: Missing project path argument"
    puts "Usage: vivado -mode batch -source sim_kpke_decrypt.tcl -tclargs <xpr_path> [max_kats]"
    exit 1
}

# 1. Setup paths and isolation
set xpr_path [file normalize [lindex $argv 0]]
set max_kats [expr {[llength $argv] >= 2 ? [lindex $argv 1] : 100}]
set script_dir [file dirname [file normalize [info script]]]
set base_out_dir [file join $script_dir "decaps_metrics"]
set ts [clock format [clock seconds] -format "%Y%m%d_%H%M%S"]
set run_dir [file join $base_out_dir "sim_decrypt_$ts"]

file mkdir $run_dir
cd $run_dir
puts "INFO: Running simulation in isolated directory: $run_dir"

# 2. Open project and harden simulation
open_project $xpr_path

# Ensure newly introduced BRAM wrapper exists in project sources.
set bram_wrap_file [file normalize [file join $script_dir ".." ".." "sources_1" "new" "bram_sdp_128x16.v"]]
if {[file exists $bram_wrap_file]} {
    if {[llength [get_files -quiet $bram_wrap_file]] == 0} {
        puts "INFO: Adding missing source file to project: $bram_wrap_file"
        add_files -norecurse $bram_wrap_file
    }
} else {
    puts "WARNING: BRAM wrapper source not found: $bram_wrap_file"
}

# Force close any existing simulation sessions in this project to prevent hangs
if {[llength [current_sim -quiet]] > 0} {
    puts "INFO: Closing previous simulation session..."
    close_sim -force
}

set_property top tb_kpke_decrypt [get_filesets sim_1]
update_compile_order -fileset sim_1
set_property xsim.simulate.runtime all [get_filesets sim_1]
set_property -name xsim.simulate.xsim.more_options -value [format "-testplusarg MAX_KATS=%d" $max_kats] -objects [get_filesets sim_1]
puts [format "INFO: Running decrypt TB with MAX_KATS=%d" $max_kats]

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
set xsim_log [file normalize [file join [get_property DIRECTORY [current_project]] "[get_property NAME [current_project]].sim" "sim_1" "behav" "xsim" "simulate.log"]]
catch {close_sim -force}

if {![file exists $xsim_log]} {
    puts "ERROR: simulate.log not found at $xsim_log"
    close_project
    exit 2
}

# Copy log to run_dir for record-keeping before closing project
file copy -force $xsim_log [file join $run_dir "sim_decrypt_simulate.log"]

set fp [open [file join $run_dir "sim_decrypt_simulate.log"] r]
set log_txt [read $fp]
close $fp

set must_have [list "ALL TESTS PASSED:"]
set must_not_have [list "TEST FAILED:" "ERROR:" "TIMEOUT" "\$stop called" "mismatch"]

foreach p $must_have {
    if {[string first $p $log_txt] < 0} {
        puts "ERROR: direct TB missing PASS marker: $p"
        close_project
        exit 3
    }
}

foreach p $must_not_have {
    if {[string first $p $log_txt] >= 0} {
        puts "ERROR: direct TB found failure marker: $p"
        close_project
        exit 4
    }
}

puts "PASS: K-PKE Decrypt TB regression gate passed"
puts "INFO: All outputs located in $run_dir"
close_project
exit 0
