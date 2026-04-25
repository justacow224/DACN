# ==============================================================================
# Regression Wrapper: tb_kpke_encrypt
# ==============================================================================
# Usage (batch):
#   vivado -mode batch -source verilog_ML_KEM/scripts/sim/run_tb_kpke_encrypt.tcl \
#     -tclargs <xpr_path> [max_kats] [kat_file]
#
# Usage (inside open Vivado project):
#   source verilog_ML_KEM/scripts/sim/run_tb_kpke_encrypt.tcl
# ==============================================================================

set opened_here 0
set max_kats 100
set script_dir [file dirname [file normalize [info script]]]
set repo_root [file normalize [file join $script_dir ".." ".."]]
set kat_file_default [file normalize [file join $repo_root "sim_1" "new" "KAT_768.txt"]]
set kat_file $kat_file_default

if {[llength $argv] >= 2} {
    set max_kats [lindex $argv 1]
}
if {[llength $argv] >= 3} {
    set kat_file [file normalize [lindex $argv 2]]
}

if {[llength [get_projects -quiet]] == 0} {
    if {[llength $argv] < 1} {
        puts "ERROR: No open project and no xpr path provided."
        puts "Usage: vivado -mode batch -source run_tb_kpke_encrypt.tcl -tclargs <xpr_path> [max_kats] [kat_file]"
        exit 1
    }
    set xpr_path [file normalize [lindex $argv 0]]
    open_project $xpr_path
    set opened_here 1
}

set kpke_core_file [file normalize [file join $repo_root "sources_1" "new" "kpke_core.v"]]
if {[file exists $kpke_core_file] && ([llength [get_files -quiet $kpke_core_file]] == 0)} {
    puts "INFO: Adding missing source file: $kpke_core_file"
    add_files -norecurse $kpke_core_file
}

set fs [get_filesets sim_1]
if {[llength $fs] == 0} {
    puts "ERROR: sim_1 fileset not found."
    if {$opened_here} { close_project }
    exit 2
}

if {[llength [current_sim -quiet]] > 0} {
    catch {close_sim -force}
}

set kat_file_arg [string map {\\ /} $kat_file]
set_property top tb_kpke_encrypt $fs
update_compile_order -fileset sim_1
set_property xsim.simulate.runtime all $fs
set_property -name xsim.simulate.xsim.more_options \
    -value [format "-testplusarg MAX_KATS=%s -testplusarg KAT_FILE=%s" $max_kats $kat_file_arg] \
    -objects $fs

set launched 0
set launch_err ""
for {set t 0} {$t < 3} {incr t} {
    if {$t > 0} {
        catch {reset_simulation -simset sim_1 -mode behavioral}
    }
    if {[catch {launch_simulation -simset sim_1 -mode behavioral} launch_err]} {
        after 1500
    } else {
        set launched 1
        break
    }
}

if {!$launched} {
    puts "ERROR: launch_simulation failed."
    puts "DETAIL: $launch_err"
    if {$opened_here} { close_project }
    exit 3
}

set proj_dir [get_property DIRECTORY [current_project]]
set proj_name [get_property NAME [current_project]]
set xsim_log [file normalize [file join $proj_dir "${proj_name}.sim" "sim_1" "behav" "xsim" "simulate.log"]]
catch {close_sim -force}

if {![file exists $xsim_log]} {
    puts "ERROR: simulate.log not found at $xsim_log"
    if {$opened_here} { close_project }
    exit 4
}

set fp [open $xsim_log r]
set log_txt [read $fp]
close $fp

if {[string first "ALL ROUNDTRIP TESTS PASSED:" $log_txt] < 0} {
    puts "ERROR: PASS marker not found in simulate.log."
    if {$opened_here} { close_project }
    exit 5
}

foreach p [list "ROUNDTRIP TEST FAILED:" "ERROR:" "TIMEOUT" "\$fatal"] {
    if {[string first $p $log_txt] >= 0} {
        puts "ERROR: Failure marker found in simulate.log: $p"
        if {$opened_here} { close_project }
        exit 6
    }
}

puts "PASS: tb_kpke_encrypt regression passed (MAX_KATS=$max_kats, KAT_FILE=$kat_file_arg)"
if {$opened_here} { close_project }
exit 0


