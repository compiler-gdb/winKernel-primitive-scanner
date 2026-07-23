#include <iostream>
#include <format>
#include <thread>
#include <chrono>

import WinKernel.Types;
import WinKernel.Process;

int main() {
    std::cout << "=========================================\n";
    std::cout << "    WinKernel v0.2.0 Integration Test    \n";
    std::cout << "=========================================\n\n";

    // 1. Types 모듈 상수 확인
    std::cout << "[1] Types Module Check:\n";
    std::cout << std::format("  - MAX_WORKERS     : {}\n", WinKernel::Constants::MAX_WORKERS);
    std::cout << std::format("  - IPC_TIMEOUT_MS  : {} ms\n\n", WinKernel::Constants::IPC_TIMEOUT_MS);

    // 2. Process 모듈 객체 생성 및 실행
    std::cout << "[2] Process Control Test:\n";
    WinKernel::Process::WorkerProcess worker;

    if (!worker.Launch(1, L"notepad.exe")) {
        std::cout << "[-] Failed to launch process.\n";
        return 1;
    }

    std::cout << std::format("  - Process PID     : {}\n", worker.GetPID());
    std::cout << std::format("  - Is Running?     : {}\n", worker.IsRunning() ? "YES" : "NO");

    // 3. 2초 대기 (타임아웃 확인)
    std::cout << "  - Waiting for 2 seconds...\n";
    if (!worker.Wait(2000)) {
        std::cout << "  - [!] Timeout hit (Process is still open as expected).\n";
    }

    // 4. 프로세스 강제 종료 (Kill)
    std::cout << "  - Killing process...\n";
    if (worker.Kill()) {
        std::cout << "  - Process killed successfully.\n";
    }

    // 5. 종료 후 상태 재확인
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    std::cout << std::format("  - Is Running now? : {}\n", worker.IsRunning() ? "YES" : "NO");
    std::cout << std::format("  - Final State Enum: {}\n\n", static_cast<int>(worker.GetState()));

    std::cout << "=========================================\n";
    std::cout << "[+] v0.2.0 Process Module Test Passed!\n";
    std::cout << "=========================================\n";

    return 0;
}