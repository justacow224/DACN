# ==============================================================================
# Gate A regression: tb_ml_kem_top with TB_BYPASS_CRYPTO=1
# ==============================================================================
# Tests AXI-Lite register semantics + AXI-MM sequencing without instantiating
# the full crypto pipeline. Used to verify infrastructure (CTRL/STATUS regs,
# WSTRB, AW/W ordering, BRESP/RRESP error handling) independently of Gate B.
#
# Usage (batch):
#   vivado -mode batch -source verilog_ML_KEM/scripts/sim/run_tb_ml_kem_top_gate_a.tcl \
#     -tclargs <xpr_path>
# ==============================================================================

set opened_here 0
set script_dir [file dirname [file normalize [info script]]]
set repo_root [file normalize [file join $script_dir ".." ".."]]

if {[llength [get_projects -quiet]] == 0} {
    if {[llength $argv] < 1} {
        puts "ERROR: No open project and no xpr path provided."
        exit 1
    }
    set xpr_path [file normalize [lindex $argv 0]]
    open_project $xpr_path
    set opened_here 1
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

set_property top tb_ml_kem_top $fs
update_compile_order -fileset sim_1
set_property xsim.simulate.runtime all $fs

# Save current xelab options to restore later
set saved_xelab_opts ""
catch {set saved_xelab_opts [get_property xsim.compile.xelab.more_options $fs]}

# Define TB_BYPASS_CRYPTO=1 for Gate A mode
set_property -name {xsim.compile.xelab.more_options} -value {-d TB_BYPASS_CRYPTO=1} -objects $fs

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

# Restore previous xelab options (so subsequent runs aren't polluted)
set_property -name {xsim.compile.xelab.more_options} -value $saved_xelab_opts -objects $fs

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

# Gate A specific marker (line 749 of tb_ml_kem_top.sv)
if {[string first "Gate A AXI infra: PASS" $log_txt] < 0} {
    puts "ERROR: Gate A PASS marker not found in simulate.log."
    if {$opened_here} { close_project }
    exit 5
}

# Top-level marker
if {[string first "tb_ml_kem_top: PASS" $log_txt] < 0} {
    puts "ERROR: tb_ml_kem_top: PASS marker not found in simulate.log."
    if {$opened_here} { close_project }
    exit 6
}

foreach p [list "ERROR:" "FATAL" "TIMEOUT" "\$fatal"] {
    if {[string first $p $log_txt] >= 0} {
        puts "ERROR: Failure marker found in simulate.log: $p"
        if {$opened_here} { close_project }
        exit 7
    }
}

puts "PASS: tb_ml_kem_top Gate A regression passed (BYPASS_CRYPTO=1)"
if {$opened_here} { close_project }
exit 0
