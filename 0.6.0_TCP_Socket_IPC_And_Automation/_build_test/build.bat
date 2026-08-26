@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "%~dp0"
cd ..
set IFC=_build_test
set FLAGS=/nologo /std:c++20 /EHsc /c /utf-8 /ifcSearchDir %IFC% /Fo:%IFC%\ /ifcOutput %IFC%\
for %%M in (WinKernel.System WinKernel.Types WinKernel.IPC WinKernel.Mutator WinKernel.Engine WinKernel.Logger WinKernel.Driver WinKernel.Process WinKernel.Worker WinKernel.Manager) do (
  cl.exe %FLAGS% %%M.ixx || (echo FAILED_AT=%%M & exit /b 1)
)
cl.exe /nologo /std:c++20 /EHsc /c /utf-8 /ifcSearchDir %IFC% /Fo:%IFC%\ main.cpp || (echo FAILED_AT=main & exit /b 1)
echo BUILD_OK
exit /b 0
