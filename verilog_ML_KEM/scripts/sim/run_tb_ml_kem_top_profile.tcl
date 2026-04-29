# =============================================================================
# Run tb_ml_kem_top with cycle profiler enabled (+define+CYCLE_PROFILE).
# Dumps per-op cycle breakdown (axi_io / compute / keccak / non_keccak /
# control / kpke_encrypt) for KAT vec #0 KeyGen + Encaps + Decaps.
#
# Usage:
#   "C:/Xilinx/2025.1/Vivado/bin/vivado.bat" -mode batch \
#     -source verilog_ML_KEM/scripts/sim/run_tb_ml_kem_top_profile.tcl \
#     -tclargs <xpr_path>
#
# Output: simulate.log will contain "=== CYCLE_PROFILE: ... ===" sections per op.
# Parse the "CSV: " lines for spreadsheet-friendly format.
# =============================================================================

if {[llength $argv] < 1} {
    puts "ERROR: Missing project path. Usage: -tclargs <xpr_path>"
    exit 1
}

set xpr_path [file normalize [lindex $argv 0]]
set repo_root [file normalize [file join [file dirname [info script]] ".." ".."]]

set fail 0
if {[catch {open_project $xpr_path} err]} {
    puts "ERROR: open_project failed: $err"
    exit 2
}
set opened_here 1

# Ensure profiler source file is in the sim_1 fileset.
set profiler_file [file normalize [file join $repo_root "sim_1" "new" "cycle_profiler.sv"]]
if {[file exists $profiler_file]} {
    if {[llength [get_files -quiet $profiler_file]] == 0} {
        puts "INFO: Adding cycle_profiler.sv to sim_1"
        add_files -fileset sim_1 -norecurse $profiler_file
    }
} else {
    puts "ERROR: cycle_profiler.sv not found at $profiler_file"
    if {$opened_here} { close_project }
    exit 3
}

set fs [get_filesets sim_1]
if {[llength [current_sim -quiet]] > 0} {
    catch {close_sim -force}
}

set_property top tb_ml_kem_top $fs
update_compile_order -fileset sim_1

# Inject the profile define.
set existing_defines [get_property verilog_define $fs]
set new_defines $existing_defines
if {[lsearch -exact $new_defines "CYCLE_PROFILE"] < 0} {
    lappend new_defines "CYCLE_PROFILE"
}
set_property verilog_define $new_defines $fs
puts "INFO: verilog_define = [get_property verilog_define $fs]"

set ts [clock format [clock seconds] -format "%Y%m%d_%H%M%S"]
set run_dir [file normalize [file join $repo_root "scripts" "AXI" "tb_ml_kem_top_metrics" "profile_${ts}"]]
file mkdir $run_dir
puts "INFO: profile run dir = $run_dir"

set launched 0
set launch_err ""
if {[catch {launch_simulation -simset sim_1 -mode behavioral} launch_err]} {
    puts "WARN: launch_simulation attempt 1 failed: $launch_err"
    catch {close_sim -force}
} else {
    set launched 1
}

if {!$launched} {
    puts "ERROR: launch_simulation failed."
    puts "DETAIL: $launch_err"
    # Restore defines so regression isn't broken.
    set restored $existing_defines
    set_property verilog_define $restored $fs
    if {$opened_here} { close_project }
    exit 4
}

set xsim_log [file normalize [file join \
    [get_property DIRECTORY [current_project]] \
    "[get_property NAME [current_project]].sim" \
    "sim_1" "behav" "xsim" "simulate.log"]]
catch {close_sim -force}

# Restore the original defines so regression TBs don't carry CYCLE_PROFILE.
set_property verilog_define $existing_defines $fs
puts "INFO: restored verilog_define = [get_property verilog_define $fs]"

if {![file exists $xsim_log]} {
    puts "ERROR: simulate.log not found at $xsim_log"
    if {$opened_here} { close_project }
    exit 5
}

set dest_log [file join $run_dir "tb_ml_kem_top_profile_simulate.log"]
file copy -force $xsim_log $dest_log

set fp [open $dest_log r]
set log_txt [read $fp]
close $fp

# Sanity gate: top-level KAT regression must still pass.
if {[string first "tb_ml_kem_top: PASS" $log_txt] < 0} {
    puts "FAIL: tb_ml_kem_top regression marker missing — sim may have errored."
    puts "INFO: full log -> $dest_log"
    if {$opened_here} { close_project }
    exit 6
}

# Extract CYCLE_PROFILE sections.
set csv_lines {}
foreach line [split $log_txt "\n"] {
    if {[regexp {^\s*CSV: (.*)$} $line _ csv_payload]} {
        lappend csv_lines $csv_payload
    }
}

set csv_path [file join $run_dir "cycle_profile.csv"]
set fp [open $csv_path w]
puts $fp "op,total,axi_io,compute,keccak,non_keccak,control,kpke_encrypt"
foreach row $csv_lines {
    puts $fp $row
}
close $fp

puts ""
puts "=========================================================="
puts "CYCLE PROFILE SUMMARY (CSV)"
puts "=========================================================="
puts "op,total,axi_io,compute,keccak,non_keccak,control,kpke_encrypt"
foreach row $csv_lines {
    puts "  $row"
}
puts ""
puts "INFO: full simulate.log -> $dest_log"
puts "INFO: csv summary       -> $csv_path"
puts "PASS: cycle profile run complete"

if {$opened_here} { close_project }
exit 0
