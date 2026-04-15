# Full non-incremental synthesis metrics flow for ml_kem_keygen
# Isolated run management: all clutter is moved to keygen_metrics/synth_<ts>/

proc copy_artifact_if_exists {src_path dst_dir} {
    if {![file exists $src_path]} {
        return
    }
    set dst_path [file join $dst_dir [file tail $src_path]]
    if {[catch {file copy -force $src_path $dst_path} copy_err]} {
        puts "WARNING: Could not copy artifact '$src_path' -> '$dst_path' ($copy_err)"
    } else {
        puts "INFO: copied artifact: $dst_path"
    }
}

if {[llength $argv] < 1} {
    puts "ERROR: Missing project path argument"
    puts "Usage: vivado -mode batch -source keygen_full_synth_metrics.tcl -tclargs <xpr_path> [jobs] [run_name]"
    exit 1
}

# 1. Setup paths and isolation
set xpr_path [file normalize [lindex $argv 0]]
set jobs [expr {[llength $argv] >= 2 ? [lindex $argv 1] : 8}]
set run_name [expr {[llength $argv] >= 3 ? [lindex $argv 2] : "synth_1"}]

set script_dir [file dirname [file normalize [info script]]]
set ts [clock format [clock seconds] -format "%Y%m%d_%H%M%S"]
set out_dir [file normalize [file join $script_dir "keygen_metrics" "synth_$ts"]]
set artifact_dir [file join $out_dir "tool_artifacts"]

file mkdir $out_dir
file mkdir $artifact_dir
cd $out_dir
puts "INFO: Running synthesis in isolated directory: $out_dir"

# 2. Open project and run synthesis
open_project $xpr_path

set synth_run [get_runs -quiet $run_name]
if {[llength $synth_run] == 0} {
    puts "ERROR: Cannot find run '$run_name'"
    close_project
    exit 2
}

# Force full non-incremental synthesis
set_property STEPS.SYNTH_DESIGN.ARGS.INCREMENTAL_MODE off $synth_run

puts "INFO: resetting run $run_name"
catch {reset_run $run_name} 

launch_runs $run_name -jobs $jobs
wait_on_run $run_name
open_run $run_name

# 3. Report generation
report_utilization -hierarchical -file [file join $out_dir util_hier_synth.rpt]
report_utilization -file [file join $out_dir util_flat_synth.rpt]
report_timing_summary -file [file join $out_dir timing_synth.rpt]
report_ram_utilization -file [file join $out_dir ram_synth.rpt]

# 4. Artifact collection
set launch_dir [file normalize [pwd]]
foreach a [list "vivado.log" "vivado.jou" "dfx_runtime.txt"] {
    copy_artifact_if_exists [file join $launch_dir $a] $artifact_dir
}

set synth_run_dir [file normalize [get_property DIRECTORY $synth_run]]
foreach a [list "runme.log" "runme.jou" "vivado.pb"] {
    copy_artifact_if_exists [file join $synth_run_dir $a] $artifact_dir
}
foreach vds [glob -nocomplain -directory $synth_run_dir *.vds] {
    copy_artifact_if_exists $vds $artifact_dir
}

puts "INFO: Metrics written to $out_dir"
puts "INFO: All logs consolidated in $artifact_dir"
close_project
exit 0
