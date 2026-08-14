#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>
#include <format>
#include <random>
#include <thread>

// 우리가 지금까지 작성한 모든 모듈 임포트
import WinKernel.Types;
import WinKernel.System;
import WinKernel.Process;
import WinKernel.IPC;
import WinKernel.Logger;
import WinKernel.Mutator;
import WinKernel.Driver;

// 타깃 드라이버 심볼릭 링크 및 IOCTL 코드 ex) HEVD 스택 오버플로우
constexpr wchar_t TARGET_DRIVER_NAME[] = L"HackSysExtremeVulnerableDriver";
constexpr DWORD TARGET_IOCTL_CODE = 0x222003;

// [추가] 커널 메모리(Non-Paged Pool) 세척을 위한 워커당 최대 실행 횟수 (200만 회)
constexpr uint64_t MAX_WORKER_ITERATIONS = 2'000'000;


// [1] 워커 프로세스 (Worker Mode)
void RunWorkerMode(DWORD workerId, const std::wstring& sessionDir) {
    // 1. 자신만의 독립된 락프리 로거 생성
    WinKernel::Logger::FuzzLogger logger(workerId, sessionDir);
    logger.Log(L"INFO", std::format(L"Worker {} started.", workerId));

    // 2. 타깃 커널 드라이버 연결 (발사대 준비)
    WinKernel::Driver::DriverController driver(TARGET_DRIVER_NAME);
    if (!driver.IsConnected()) {
        logger.Log(L"ERROR", L"Failed to connect to target driver. Exiting.");
        return;
    }
    logger.Log(L"INFO", L"Successfully connected to Driver.");

    // 3. 변이 엔진(Mutator) 초기화 (std::random_device로 진짜 난수 시드 추출)
    uint32_t seed = std::random_device{}();
    WinKernel::Mutator::MutatorEngine mutator(seed);
    logger.Log(L"INFO", std::format(L"Mutator initialized with Seed: {}", seed));

    // 4. 기본 페이로드 준비 (예: 2048바이트의 'A' 배열)
    std::vector<uint8_t> basePayload(2048, 0x41);
    std::vector<uint8_t> outputBuffer(1024, 0x00);

    // 5. 무한 퍼징 루프 시작
    uint64_t iteration = 0;
    while (true) {
        iteration++;

        // Mutate 실행
        std::vector<uint8_t> fuzzPayload = basePayload;
        mutator.Mutate(fuzzPayload);

        if (iteration % 1000000 == 0) { // 로그 폭주 방지를 위해 100만 번 단위로 생존 신고
            logger.Log(L"FUZZ", std::format(L"Iteration {} running...", iteration));
        }

        // 지정된 횟수(200만 번)에 도달하면 커널 자원 청소를 위해 정상 종료
        if (iteration >= MAX_WORKER_ITERATIONS) {
            logger.Log(L"INFO", std::format(L"Reached MAX_WORKER_ITERATIONS ({}). Exiting for kernel resource recycling.", MAX_WORKER_ITERATIONS));
            return; // Exit Code 0 반환하며 정상 종료 (마스터가 새 워커로 교체해줌)
        }

        // IOCTL 패킷 전송.
        bool result = driver.SendIoctl(TARGET_IOCTL_CODE, fuzzPayload, outputBuffer);

        if (!result) {
            // 드라이버가 뻗었거나 연결이 끊어짐 (크래시 확률 높음)
            logger.Log(L"CRASH", std::format(L"IOCTL Failed at Iteration {}. Saving Seed...", iteration));
            logger.SaveCrashSeed(seed, fuzzPayload);
            break; // 발견 시 무한루프 탈출
        }
    }
}


// [2] 마스터 프로세스 (Master Mode)
void RunMasterMode() {
    std::wcout << L"[+] Starting WinKernel Fuzzer Master Process...\n";

    // 1. 이번 퍼징 세션의 고유 폴더 생성
    std::wstring sessionDir = WinKernel::Logger::FuzzLogger::GenerateSessionDirectoryName();
    std::wcout << L"[+] Session Directory Created: " << sessionDir << L"\n";

    // 2. 시스템 논리 코어 수 확인하여 워커 개수 최적화
    DWORD coreCount = WinKernel::System::GetLogicalCoreCount();
    DWORD workerCount = min((max(1UL, coreCount - 2)), WinKernel::Constants::MAX_WORKERS);
    std::wcout << L"[+] Logical Cores: " << coreCount << L". Spawning " << workerCount << L" workers.\n";

    // 3. 자식 프로세스(워커) 생성
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    std::vector<WinKernel::Process::WorkerProcess> workers;

    for (DWORD i = 0; i < workerCount; ++i) {
        std::wstring cmdLine = std::format(L"\"{}\" --worker {} \"{}\"", exePath, i, sessionDir);

        WinKernel::Process::WorkerProcess worker;
        if (worker.Launch(i, cmdLine.c_str())) {
            std::wcout << L"  -> Worker " << i << L" launched successfully. (PID: " << worker.GetPID() << L")\n";
            workers.push_back(std::move(worker));
        }
        else {
            std::wcout << L"  -> [!] Failed to launch Worker " << i << L"\n";
        }
    }

    std::wcout << L"[+] All workers are running. Press Ctrl+C to terminate.\n";

    // 4. 워커 프로세스 상태 모니터링 및 자동 재활용 (Watchdog + Recycle)
    std::vector<int> hangCounters(workers.size(), 0);

    // 마스터가 멈추지 않고 워커를 영구히 재생성하며 돌도록 영구 루프 전환
    while (true) {
        for (size_t i = 0; i < workers.size(); ++i) {
            auto& worker = workers[i];

            // 1초(1000ms) 동안 워커 상태 대기
            if (worker.Wait(1000)) {
                // Wait()가 true를 반환했다면 프로세스가 종료된 것 (리셋 종료, 크래시, 또는 Hang 종료)
                std::wcout << std::format(L"[+] Worker {} (Old PID: {}) terminated/recycled. Respawning...\n", i, worker.GetPID());

                // 워커 새로 생성 (새로운 PID, 새로운 난수 시드, 깨끗한 커널 상태)
                std::wstring cmdLine = std::format(L"\"{}\" --worker {} \"{}\"", exePath, static_cast<DWORD>(i), sessionDir);
                WinKernel::Process::WorkerProcess newWorker;

                if (newWorker.Launch(static_cast<DWORD>(i), cmdLine.c_str())) {
                    std::wcout << std::format(L"  -> Worker {} respawned successfully. (New PID: {})\n", i, newWorker.GetPID());
                    worker = std::move(newWorker); // vector 내의 기존 워커 객체를 새 워커로 교체
                    hangCounters[i] = 0;           // 행 카운터 초기화
                }
                else {
                    std::wcout << std::format(L"  -> [!] Failed to respawn Worker {}\n", i);
                }
            }
            else {
                // 1초가 지났는데도 아직 실행 중인 상태
                if (worker.IsRunning()) {
                    hangCounters[i]++; // 응답 지연 카운터 증가

                    // 10초 이상 응답이 없으면 Hang으로 판단하고 강제 종료 (다음 루프에서 자동 Respawn됨)
                    if (hangCounters[i] >= 10) {
                        std::wcout << std::format(L"[!] Warning: Worker {} (PID: {}) is HANGING. Terminating...\n", i, worker.GetPID());
                        worker.Kill(1);
                    }
                }
            }
        }
    }
}


// [3] 진입점 (Entry Point)
int wmain(int argc, wchar_t* argv[]) {
    // 인자에 --worker가 있으면 워커 모드로 분기
    if (argc >= 4 && std::wstring(argv[1]) == L"--worker") {
        DWORD workerId = static_cast<DWORD>(std::wcstoul(argv[2], nullptr, 10));
        std::wstring sessionDir = argv[3];

        RunWorkerMode(workerId, sessionDir);
        return 0;
    }

    // 인자가 없으면 마스터 모드 실행
    RunMasterMode();
    return 0;
}