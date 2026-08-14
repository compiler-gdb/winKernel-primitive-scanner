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

// [추가] 커널 메모리(Non-Paged Pool) 세척을 위한 워커당 최대 실행 횟수 (700만 회)
constexpr uint64_t MAX_WORKER_ITERATIONS = 7'000'000;


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
    //logger.Log(L"INFO", std::format(L"Mutator initialized with Seed: {}", seed));

    DWORD currentPid = GetCurrentProcessId();

    // 프로세스 구분선 배너 
    logger.Log(L"---", L"================================================================================");
    logger.Log(L"NEW_RUN", std::format(
        L"Worker {} Lifecycle Started | PID: {} | Seed: 0x{:08X} | Target IOCTL: 0x{:X}",
        workerId, currentPid, seed, TARGET_IOCTL_CODE
    ));
    logger.Log(L"---", L"================================================================================");

    // 4. 기본 페이로드 준비 (예: 2048바이트의 'A' 배열)
    std::vector<uint8_t> basePayload(2048, 0x41);
    std::vector<uint8_t> outputBuffer(1024, 0x00);

    // 5. 무한 퍼징 루프 시작
    uint64_t iteration = 0;
    auto startTime = std::chrono::steady_clock::now();
    while (true) {
        iteration++;

        // Mutate 실행
        std::vector<uint8_t> fuzzPayload = basePayload;
        mutator.Mutate(fuzzPayload);

        //if (iteration % 1000000 == 0) { // 로그 폭주 방지를 위해 100만 번 단위로 생존 신고
        //    logger.Log(L"FUZZ", std::format(L"Iteration {} running...", iteration));
        //}

        // 지정된 횟수(700만 번)에 도달하면 커널 자원 청소를 위해 정상 종료
        if (iteration >= MAX_WORKER_ITERATIONS) {
            auto endTime = std::chrono::steady_clock::now();
            std::chrono::duration<double> elapsed = endTime - startTime;
            double execSpeed = iteration / elapsed.count();

            logger.Log(L"SUMMARY", std::format(
                L"Worker {} completed {} iterations in {:.2f}s ({:.0f} exec/s). Recycling...",
                workerId, iteration, elapsed.count(), execSpeed
            ));
            return;
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

    // 4. 워커 프로세스 상태 모니터링 (논블로킹 감시 + 50ms 주기)
    std::vector<int> hangCounters(workers.size(), 0);

    while (true) {
        for (size_t i = 0; i < workers.size(); ++i) {
            auto& worker = workers[i];

            // Wait()함수는 Process.ixx 참고.
            // 타임아웃에 0을 주었기에 대기 시간 없이 프로세스 핸들의 신호 상태만을 읽고 결과를 반환합니다.

            // 워커가 아직 지정한 횟수에 따라서 실행 중일 때는 OS 프로세스 HANDLE이 "Non-Signaled" 상태입니다.
            // WAIT_TIMEOUT을 반환하므로 Wait(0)은 false가 됩니다. if(false)가 되므로 else 구문에 들어갑니다.
            // WaitForSingleObject(hProcess_, timeoutMs);로 비교하기 때문에 hprocess_라는 번호표로 각 worker에 대한 프로세스 종료 여부를 따지게 됩니다.
            // 마스터 프로세스를 관리하는 Manager.ixx의 InitializeAndLaunchAll로 각 턴마다 worker Process객체를 생성하고 Launch를 호출하며 핸들을 가진 객체를 vector에 쌓았습니다.
            if (worker.Wait(0)) {

                // 지정한 횟수만큼 실행 후 프로세스가 종료됐을 때 프로세스가 죽으며 OS가 HANDLE을 Signaled 상태로 바꿉니다. OS가 WAIT_OBJECT_0을 반환하므로 Wait(0)은 true가 되며 if문에 들어오게 됩니다.
                // 우리는 WAIT_OBJECT_0 신호를 기다리고 있었습니다.
                std::wcout << std::format(L"[+] Worker {} (Old PID: {}) finished/recycled. Respawning...\n", i, worker.GetPID());

                // 확인이 0ms이므로 워커 즉시 부활
                std::wstring cmdLine = std::format(L"\"{}\" --worker {} \"{}\"", exePath, static_cast<DWORD>(i), sessionDir);
                WinKernel::Process::WorkerProcess newWorker;

                if (newWorker.Launch(static_cast<DWORD>(i), cmdLine.c_str())) {
                    worker = std::move(newWorker);
                    hangCounters[i] = 0; // 카운터 초기화
                }
            }
            else {
                // 실행 중인 경우 Hang 체크 (50ms마다 1씩 증가)
                if (worker.IsRunning()) {
                    hangCounters[i]++;

                    // [수정] 기존 10초에서 1분으로 Hang 판정 시간을 늘렸습니다. 0.5.1에서 프로세스 생명 주기가 8초였는데 4틱의 불량으로도 Hang판정을 받을 수 있기 때문에 넉넉하게 수정하였습니다.
                    if (hangCounters[i] >= 600) {
                        std::wcout << std::format(L"[!] Warning: Worker {} (PID: {}) is HANGING. Terminating...\n", i, worker.GetPID());
                        worker.Kill(1);
                    }
                }
            }
        }
        // Sleep 없이 while(true)를 돌면 마스터 스레드가 CPU 코어 1개를 100% 갉아먹게 됩니다
        // 마스터 CPU 점유율을 0~1%대로 유지하기 위한 휴식 (50ms)
        Sleep(50);
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