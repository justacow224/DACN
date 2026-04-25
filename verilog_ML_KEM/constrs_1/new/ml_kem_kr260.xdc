# ================================================================
# ml_kem_kr260.xdc — user constraints for ml_kem_top inside BD
#
# Clock source: PS PL_CLK0 (100 MHz) is auto-constrained by the BD
# (Zynq UltraScale+ IP). Name at wrapper scope: clk_pl_0, period 10.000 ns.
# Do NOT redeclare it here — `create_clock [get_ports clk]` would fail
# because the wrapper has no top-level port named `clk`.
#
# This file is reserved for implementation hints that the BD does not
# auto-generate: fanout caps, memory style, intentional exceptions.
# ================================================================


# ---------------------------------------------------------------
# Fanout cap on the Keccak sponge FSM state register.
#
# Batch6 bitstream failed encaps KAT on-board (ct mismatch, ss match)
# despite `tb_ml_kem_top` passing in sim. Root cause: control-net
# fanout ~1680 on `u_encaps/u_keccak/state[1]`, WNS 0.797 ns at TT.
# Under SS corner + junction temperature, setup margin collapsed ->
# SHAKE256 PRF squeeze produced near-zero (r, e1, e2), making
# v ~= Decompress_1(m) and c2 nibbles degenerate to {0, 8}.
#
# Replicating the state register (MAX_FANOUT 64) cuts net delay on the
# critical path, restoring real silicon margin without touching RTL.
# Applies to all three Keccak instances (keygen/encaps/decaps).
# ---------------------------------------------------------------

set_property MAX_FANOUT 64 [get_cells -hier -filter {NAME =~ *u_keccak/state_reg*}]

# Note: fsm_state_reg / finalize_keccak_reg existed in an earlier RTL revision
# but are no longer synthesized as cells with those names in the current build
# (the 2025-04 rebuild log showed "No cells matched"). Rely on Vivado's
# automatic BUFG insertion in Phase 4.1.1.1 for the remaining high-fanout
# Keccak nets (u_*/u_keccak/i___232_n_0, state_out[1599]_i_1_*_n_0, A) —
# 16 BUFGs were inserted automatically on that pass.


# ---------------------------------------------------------------
# Force BRAM inference for zeta / inv_zeta ROM.
#
# At LUT-tight utilization (batch6 closed Gate 1 at ~40% LUT), tool may
# merge zeta_rom into distributed LUTRAM to save BRAM. That pushes the
# critical path of ntt/inv_ntt butterflies through LUT chains and hurts
# Fmax. Pin to BRAM for deterministic timing.
# ---------------------------------------------------------------

set_property ROM_STYLE BLOCK [get_cells -hier -filter {NAME =~ *zeta_rom*}]
set_property ROM_STYLE BLOCK [get_cells -hier -filter {NAME =~ *inv_zeta_rom*}]


# ---------------------------------------------------------------
# Scope: this file is used in synth + impl only.
# Simulation reads RTL without constraints — run this once if the
# project was ever set to USED_IN_SIMULATION=1 for this xdc.
#
#   set_property USED_IN_SIMULATION    0 [get_files *ml_kem_kr260.xdc]
#   set_property USED_IN_SYNTHESIS     1 [get_files *ml_kem_kr260.xdc]
#   set_property USED_IN_IMPLEMENTATION 1 [get_files *ml_kem_kr260.xdc]
# ---------------------------------------------------------------

create_clock -period 10.000 -name ooc_clk [get_ports clk]
