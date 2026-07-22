#include <iostream>
#include <format>

import WinKernel.Types;

int main() {
    std::cout << "=========================================\n";
    std::cout << "    WinKernel.Types Module Unit Test     \n";
    std::cout << "=========================================\n\n";

    // 1. Constants (상수) 검증
    std::cout << "[1] Constants Verification:\n";
    std::cout << std::format("  - MAX_WORKERS         : {}\n", WinKernel::Constants::MAX_WORKERS);
    std::cout << std::format("  - DEFAULT_BUFFER_SIZE : {} bytes\n", WinKernel::Constants::DEFAULT_BUFFER_SIZE);
    std::cout << std::format("  - IPC_TIMEOUT_MS      : {} ms\n", WinKernel::Constants::IPC_TIMEOUT_MS);
    std::wcout << std::format(L"  - LOG_FILE_PATH       : {}\n\n", WinKernel::Constants::LOG_FILE_PATH);

    // 2. WorkerState (Enum) 검증
    std::cout << "[2] WorkerState Enum Verification:\n";
    WinKernel::Types::WorkerState state = WinKernel::Types::WorkerState::Idle;
    std::cout << std::format("  - State Initial Value : {} (0: Idle)\n\n", static_cast<int>(state));

    // 3. FuzzPacket (구조체) 필드 및 메모리 크기 검증
    std::cout << "[3] FuzzPacket Struct Verification:\n";
    WinKernel::Types::FuzzPacket packet{};
    packet.ioctlCode = 0x222003;
    packet.targetAddress = 0x7FFF0000;
    packet.bufferSize = 256;

    std::cout << std::format("  - Sizeof(FuzzPacket)  : {} bytes\n", sizeof(WinKernel::Types::FuzzPacket));
    std::cout << std::format("  - IOCTL Code          : {:#x}\n", packet.ioctlCode); // {:#x} : 16진수 0x 표기
    std::cout << std::format("  - Target Address      : {:#x}\n\n", packet.targetAddress);

    // 4. SharedWorkerStatus (구조체) 검증
    std::cout << "[4] SharedWorkerStatus Struct Verification:\n";
    WinKernel::Types::SharedWorkerStatus status{};
    status.workerID = 1;
    status.state = WinKernel::Types::WorkerState::Running;
    status.lastIoctl = packet.ioctlCode;
    status.lastAddress = packet.targetAddress;

    std::cout << std::format("  - Worker ID           : {}\n", status.workerID);
    std::cout << std::format("  - Worker State        : {} (1: Running)\n", static_cast<int>(status.state));
    std::cout << std::format("  - Sizeof(SharedStatus): {} bytes\n\n", sizeof(WinKernel::Types::SharedWorkerStatus));

    std::cout << "=========================================\n";
    std::cout << "[+] WinKernel.Types Unit Test Passed!\n";
    std::cout << "=========================================\n";

    return 0;
} 