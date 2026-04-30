# Generate hierarchical utilization report from current impl_1 checkpoint.
# Usage:
#   "C:/Xilinx/2025.1/Vivado/bin/vivado.bat" -mode batch \
#     -source verilog_ML_KEM/scripts/AXI/report_hier_util.tcl \
#     -tclargs D:/HCMUT/Year_4/252/CA/Vivado/verilog_ML_KEM/verilog_ML_KEM.xpr

if {[llength $argv] < 1} {
    puts "ERROR: Missing project path"
    exit 1
}

set xpr_path [file normalize [lindex $argv 0]]
open_project $xpr_path

# Open the routed (post-impl) design
open_run impl_1

set ts [clock format [clock seconds] -format "%Y%m%d_%H%M%S"]
set out_dir [file normalize "verilog_ML_KEM/scripts/AXI/util_hier_${ts}"]
file mkdir $out_dir

# 1) Full hierarchical utilization (all levels)
report_utilization -hierarchical -file [file join $out_dir "util_hier_full.rpt"]
puts "INFO: full hier   -> [file join $out_dir util_hier_full.rpt]"

# 2) Top-3-levels summary (easier to digest for thesis writeup)
report_utilization -hierarchical -hierarchical_depth 3 \
    -file [file join $out_dir "util_hier_depth3.rpt"]
puts "INFO: depth-3     -> [file join $out_dir util_hier_depth3.rpt]"

# 3) Per-major-cell drill-down (keygen / encaps / decaps / keccak)
foreach hier_pat {
    "*u_keccak*"
    "*u_keygen*"
    "*u_encaps*"
    "*u_decaps*"
    "*u_inv_ntt*"
    "*u_ntt*"
} {
    set cells [get_cells -quiet -hier -filter "NAME =~ $hier_pat"]
    if {[llength $cells] > 0} {
        # Take only the top-most match (closest to root)
        set top_cell [lindex [lsort -dictionary $cells] 0]
        set safe_name [string map {/ _ * x} $top_cell]
        set rpt_file [file join $out_dir "util_${safe_name}.rpt"]
        report_utilization -cells $top_cell -file $rpt_file
        puts "INFO: $top_cell -> $rpt_file"
    }
}

# 4) Quick text summary of top consumers (printed to stdout)
puts ""
puts "================================================================"
puts "TOP 10 LUT CONSUMERS (by hierarchical cell)"
puts "================================================================"
set all_cells [get_cells -hier -filter {IS_PRIMITIVE==0 && NAME != ""}]
set rows {}
foreach c $all_cells {
    set lut_count 0
    foreach prim [get_cells -hier -filter "NAME=~$c/* && PRIMITIVE_GROUP==LUT"] {
        incr lut_count
    }
    if {$lut_count > 0} {
        lappend rows [list $lut_count $c]
    }
}
set rows_sorted [lsort -decreasing -integer -index 0 $rows]
foreach row [lrange $rows_sorted 0 9] {
    puts [format "  %6d LUT  %s" [lindex $row 0] [lindex $row 1]]
}

close_project
puts ""
puts "INFO: Reports in $out_dir"
exit 0
