# ==============================================================================
# Simulation Script: tb_ml_kem_top (Gate A AXI infra + Gate B KAT vec #0)
# ==============================================================================
# CLEANUP (if locked): taskkill /F /IM xsimk.exe /T & taskkill /F /IM xsim.exe /T & taskkill /F /IM vivado.bat /T & taskkill /F /IM vivado.exe /T
#
# PRE-REQUISITE: run once to generate KAT0 .mem files
#   python verilog_ML_KEM/scripts/extract_kat0.py
#
# EXECUTION (CMD):
#   cd /d D:\HCMUT\Year_4\252\CA\Source\DACN && "C:\Xilinx\2025.1\Vivado\bin\vivado.bat" -mode batch -source verilog_ML_KEM/scripts/AXI/sim_tb_ml_kem_top.tcl -tclargs D:/HCMUT/Year_4/252/CA/Vivado/verilog_ML_KEM/verilog_ML_KEM.xpr
# ==============================================================================

if {[llength $argv] < 1} {
    puts "ERROR: Missing project path argument"
    puts "Usage: vivado -mode batch -source sim_tb_ml_kem_top.tcl -tclargs <xpr_path>"
    exit 1
}

set xpr_path [file normalize [lindex $argv 0]]
set script_dir [file dirname [file normalize [info script]]]
set base_out_dir [file join $script_dir "tb_ml_kem_top_metrics"]
set ts [clock format [clock seconds] -format "%Y%m%d_%H%M%S"]
set run_dir [file join $base_out_dir "sim_$ts"]

file mkdir $run_dir
cd $run_dir
puts "INFO: Running simulation in isolated directory: $run_dir"

open_project $xpr_path

if {[llength [current_sim -quiet]] > 0} {
    puts "INFO: Closing previous simulation session..."
    close_sim -force
}

set fs [get_filesets sim_1]
set_property top tb_ml_kem_top $fs
update_compile_order -fileset sim_1
set_property xsim.simulate.runtime all $fs

proc run_and_check {gate_name bypass_value run_dir must_have must_not_have} {
    set fs [get_filesets sim_1]
    puts "INFO: Running $gate_name (TB_BYPASS_CRYPTO=$bypass_value)"

    set_property verilog_define [list [format "TB_BYPASS_CRYPTO=%d" $bypass_value]] $fs
    set_property -name xsim.elaborate.xelab.more_options -value "" -objects $fs
    set_property -name xsim.simulate.xsim.more_options -value "" -objects $fs
    update_compile_order -fileset sim_1

    set launched 0
    set launch_err ""
    for {set t 0} {$t < 5} {incr t} {
        catch {reset_simulation -simset sim_1 -mode behavioral}
        if {[catch {launch_simulation -simset sim_1 -mode behavioral} launch_err]} {
            after 2000
        } else {
            set launched 1
            break
        }
    }

    if {!$launched} {
        puts "ERROR: launch_simulation failed for $gate_name after retries."
        puts "DETAIL: $launch_err"
        close_project
        exit 5
    }

    set xsim_log [file normalize [file join [get_property DIRECTORY [current_project]] "[get_property NAME [current_project]].sim" "sim_1" "behav" "xsim" "simulate.log"]]
    catch {close_sim -force}

    if {![file exists $xsim_log]} {
        puts "ERROR: simulate.log not found at $xsim_log"
        close_project
        exit 2
    }

    set log_dst [file join $run_dir "${gate_name}_simulate.log"]
    file copy -force $xsim_log $log_dst

    set fp [open $log_dst r]
    set log_txt [read $fp]
    close $fp

    set found_fail 0
    foreach p $must_not_have {
        if {[string first $p $log_txt] >= 0} {
            puts "FAIL: $gate_name hit failure marker: $p"
            set found_fail 1
        }
    }

    if {$found_fail} {
        puts "INFO: full log -> $log_dst"
        close_project
        exit 4
    }

    foreach p $must_have {
        if {[string first $p $log_txt] < 0} {
            puts "FAIL: $gate_name missing PASS marker: $p"
            puts "INFO: full log -> $log_dst"
            close_project
            exit 3
        }
    }

    puts "PASS: $gate_name complete"
}

set common_must_not [list \
    "mismatch" \
    "TIMEOUT" \
    "\$fatal" \
    "\$stop called"]

run_and_check "gate_a" 1 $run_dir \
    [list "Gate A AXI infra: PASS" "tb_ml_kem_top: PASS"] \
    $common_must_not

run_and_check "gate_b" 0 $run_dir \
    [list \
        "Gate B KAT KeyGen: pk + sk match (vec #0)" \
        "Gate B KAT Encaps: ct + ss match (vec #0)" \
        "Gate B KAT Decaps: ss match (vec #0)" \
        "tb_ml_kem_top: PASS"] \
    $common_must_not

puts "PASS: tb_ml_kem_top Gate A+B regression complete"
puts "INFO: All outputs located in $run_dir"
close_project
exit 0
