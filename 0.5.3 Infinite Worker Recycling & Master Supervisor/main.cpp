#include <iostream>
#include <string>
#include <Windows.h>

import WinKernel.Manager;
import WinKernel.Worker;

int wmain(int argc, wchar_t* argv[]) {
    // 1. 워커 모드 분기 (인자가 --worker 인 경우)
    if (argc >= 4 && std::wstring(argv[1]) == L"--worker") {
        DWORD workerId = static_cast<DWORD>(std::wcstoul(argv[2], nullptr, 10));
        std::wstring sessionDir = argv[3];

        WinKernel::Worker::Run(workerId, sessionDir);
        return 0;
    }

    // 2. 마스터 모드 진입 (인자가 없는 기본 실행)
    WinKernel::Manager::MasterController master;
    return master.Run();
}