@echo off
REM Wrapper to ensure Vivado bin is on PATH for child sim spawn (xvlog/xelab/xsim).
REM Usage: _run_vivado_sim.bat <tcl_script> <xpr_path> [extra_args...]

setlocal
set "PATH=C:\Xilinx\2025.1\Vivado\bin;C:\Xilinx\2025.1\Vivado\bin\unwrapped\win64.o;%PATH%"
set "XILINX_VIVADO=C:\Xilinx\2025.1\Vivado"

set TCL_SCRIPT=%~1
shift
set XPR_PATH=%~1
shift
set EXTRA_ARGS=%~1

call "C:\Xilinx\2025.1\Vivado\bin\vivado.bat" -mode batch -source %TCL_SCRIPT% -tclargs %XPR_PATH% %EXTRA_ARGS%
exit /b %errorlevel%
