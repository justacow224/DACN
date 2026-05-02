# ==============================================================================
# Add ml_kem_top_0/irq_done -> zynq_ultra_ps_e_0/pl_ps_irq0[0] routing.
# ==============================================================================
# Refreshes ml_kem_top_0 cell to pick up the new `irq_done` output port,
# inserts xlconcat (NUM_PORTS=1) and xlconstant for the upper 7 bits of the
# 8-bit pl_ps_irq0 vector, wires irq_done -> concat[0] -> pl_ps_irq0.
# Re-validates BD, regenerates output products. Caller should follow up with
# clock_bump_115mhz.tcl (target=125) to rebuild the bitstream.
#
# EXECUTION:
#   "C:/Xilinx/2025.1/Vivado/bin/vivado.bat" -mode batch \
#     -source verilog_ML_KEM/scripts/AXI/add_irq_route.tcl \
#     -tclargs D:/HCMUT/Year_4/252/CA/Vivado/verilog_ML_KEM/verilog_ML_KEM.xpr
# ==============================================================================

if {[llength $argv] < 1} {
    puts "ERROR: Missing project path"
    exit 1
}

set xpr_path [file normalize [lindex $argv 0]]
open_project $xpr_path

set_property top ml_kem_bd_wrapper [current_fileset]
update_compile_order -fileset sources_1

set bd_file [get_files ml_kem_bd.bd]
open_bd_design $bd_file

# Refresh ml_kem_top module reference by delete + clear IP cache + recreate.
# Vivado 2025.1 caches the module port list in the IP xci files; without
# clearing the cache, recreating the cell sees the OLD port list.
puts "INFO: deleting ml_kem_top_0 cell + clearing IP cache..."
delete_bd_objs [get_bd_cells ml_kem_top_0]

# Remove cached IP files for ml_kem_top_0_0
set proj_dir [get_property DIRECTORY [current_project]]
foreach pattern [list \
    "$proj_dir/*.srcs/sources_1/bd/ml_kem_bd/ip/ml_kem_bd_ml_kem_top_0_*" \
    "$proj_dir/*.gen/sources_1/bd/ml_kem_bd/ip/ml_kem_bd_ml_kem_top_0_*" \
    "$proj_dir/*.cache/ip/*/ml_kem_bd_ml_kem_top_0_*" \
] {
    foreach f [glob -nocomplain $pattern] {
        puts "INFO: removing $f"
        file delete -force $f
    }
}

# Force-reload the source so the BD parser sees the new port.
set ml_top_v [get_files -of_objects [get_filesets sources_1] ml_kem_top.v]
puts "INFO: ml_kem_top.v file: $ml_top_v"
if {$ml_top_v ne ""} {
    set ml_top_v_norm [file normalize $ml_top_v]
    remove_files -fileset sources_1 $ml_top_v
    add_files -fileset sources_1 -norecurse $ml_top_v_norm
    update_compile_order -fileset sources_1
}

puts "INFO: closing BD + project to flush module-ref cache..."
save_bd_design
close_bd_design [current_bd_design]
close_project
puts "INFO: re-opening project for fresh module-ref read..."
open_project $xpr_path
set_property top ml_kem_bd_wrapper [current_fileset]
update_compile_order -fileset sources_1
open_bd_design [get_files ml_kem_bd.bd]

puts "INFO: recreating ml_kem_top_0 with fresh module ref..."
create_bd_cell -type module -reference ml_kem_top ml_kem_top_0

# Confirm the new port exists.
set irq_pin [get_bd_pins -quiet ml_kem_top_0/irq_done]
if {$irq_pin eq ""} {
    puts "ERROR: ml_kem_top_0/irq_done not visible after recreate."
    puts "       Confirm ml_kem_top.v has 'output wire irq_done' in its ports."
    close_project
    exit 1
}
puts "INFO: ml_kem_top_0/irq_done visible. Restoring connections..."

# clk -> pl_clk0 net
connect_bd_net [get_bd_pins ml_kem_top_0/clk] \
               [get_bd_pins zynq_ultra_ps_e_0/pl_clk0]
# rst_n -> rst_ps8_0_99M/interconnect_aresetn
connect_bd_net [get_bd_pins ml_kem_top_0/rst_n] \
               [get_bd_pins rst_ps8_0_99M/interconnect_aresetn]
# s_axi <- axi_smc/M00_AXI (PS AXI-Lite host)
connect_bd_intf_net [get_bd_intf_pins ml_kem_top_0/s_axi] \
                    [get_bd_intf_pins axi_smc/M00_AXI]
# m_axi -> axi_smc_1/S00_AXI (to PS HPC0)
connect_bd_intf_net [get_bd_intf_pins ml_kem_top_0/m_axi] \
                    [get_bd_intf_pins axi_smc_1/S00_AXI]

# Reassign the AXI-Lite address space + address map for ml_kem_top_0/s_axi.
assign_bd_address -target_address_space \
    [get_bd_addr_spaces zynq_ultra_ps_e_0/Data] \
    [get_bd_addr_segs {ml_kem_top_0/s_axi/reg0}] -force
# Reassign the AXI-MM master address map (HPC0_DDR_LOW).
assign_bd_address -target_address_space \
    [get_bd_addr_spaces ml_kem_top_0/m_axi] \
    [get_bd_addr_segs {zynq_ultra_ps_e_0/SAXIGP0/HPC0_DDR_LOW}] -force
# Mirror the original BD: explicitly exclude HPC0_DDR_HIGH from the master.
exclude_bd_addr_seg -target_address_space \
    [get_bd_addr_spaces ml_kem_top_0/m_axi] \
    [get_bd_addr_segs {zynq_ultra_ps_e_0/SAXIGP0/HPC0_DDR_HIGH}]

# Confirm the port is now visible.
set irq_pin [get_bd_pins -quiet ml_kem_top_0/irq_done]
if {$irq_pin eq ""} {
    puts "ERROR: ml_kem_top_0/irq_done not visible after refresh."
    puts "       Check that ml_kem_top.v compiled with the new output port."
    close_project
    exit 1
}
puts "INFO: ml_kem_top_0/irq_done OK."

# Add xlconcat: pack irq_done into bit[0] of an 8-bit vector for pl_ps_irq0.
# NUM_PORTS=8, IN0_WIDTH=1, IN1..IN7_WIDTH=1 -> dout is 8 bits.
if {[llength [get_bd_cells -quiet irq_concat]] == 0} {
    puts "INFO: creating irq_concat (xlconcat 8-bit)..."
    create_bd_cell -type ip -vlnv xilinx.com:ip:xlconcat:2.1 irq_concat
    set_property -dict [list \
        CONFIG.NUM_PORTS {8} \
        CONFIG.IN0_WIDTH {1} CONFIG.IN1_WIDTH {1} CONFIG.IN2_WIDTH {1} \
        CONFIG.IN3_WIDTH {1} CONFIG.IN4_WIDTH {1} CONFIG.IN5_WIDTH {1} \
        CONFIG.IN6_WIDTH {1} CONFIG.IN7_WIDTH {1} \
    ] [get_bd_cells irq_concat]
}

# Constant 0 for unused IRQ inputs (In1..In7).
if {[llength [get_bd_cells -quiet irq_zero]] == 0} {
    puts "INFO: creating irq_zero (xlconstant 1-bit 0)..."
    create_bd_cell -type ip -vlnv xilinx.com:ip:xlconstant:1.1 irq_zero
    set_property -dict [list \
        CONFIG.CONST_WIDTH {1} \
        CONFIG.CONST_VAL   {0} \
    ] [get_bd_cells irq_zero]
}

# Wire irq_done to concat[0].
if {[llength [get_bd_nets -quiet -of_objects [get_bd_pins ml_kem_top_0/irq_done]]] == 0} {
    connect_bd_net [get_bd_pins ml_kem_top_0/irq_done] \
                   [get_bd_pins irq_concat/In0]
}

# Wire zero to concat[1..7].
foreach idx {1 2 3 4 5 6 7} {
    if {[llength [get_bd_nets -quiet -of_objects [get_bd_pins irq_concat/In${idx}]]] == 0} {
        connect_bd_net [get_bd_pins irq_zero/dout] \
                       [get_bd_pins irq_concat/In${idx}]
    }
}

# Wire concat/dout -> zynq_ultra_ps_e_0/pl_ps_irq0
set zynq_irq_pin [get_bd_pins -quiet zynq_ultra_ps_e_0/pl_ps_irq0]
if {$zynq_irq_pin eq ""} {
    puts "ERROR: zynq_ultra_ps_e_0/pl_ps_irq0 not present. Check PSU__USE__IRQ0."
    close_project
    exit 1
}
if {[llength [get_bd_nets -quiet -of_objects $zynq_irq_pin]] == 0} {
    connect_bd_net [get_bd_pins irq_concat/dout] $zynq_irq_pin
}

puts "INFO: validating BD..."
set vd [validate_bd_design]
if {[string first "ERROR" $vd] >= 0} {
    puts "ERROR: BD validation failed:"
    puts $vd
    close_project
    exit 2
}
save_bd_design

# Regenerate output products + remake HDL wrapper.
close_bd_design [current_bd_design]
reset_target all  [get_files ml_kem_bd.bd]
generate_target all [get_files ml_kem_bd.bd]

set wrapper_file [make_wrapper -files [get_files ml_kem_bd.bd] -top -force]
add_files -norecurse -force $wrapper_file
update_compile_order -fileset sources_1

puts "PASS: irq_done routed to pl_ps_irq0[0]. Run clock_bump_115mhz.tcl 125 to rebuild bitstream."

close_project
exit 0
