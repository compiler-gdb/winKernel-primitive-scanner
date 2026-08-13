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

        // 커널 타깃은 예외 발생 시 OS 전체가 죽는 BSOD(Blue Screen)를 유발합니다. 따라서 드라이버로 패킷을 쏘기 직전에 현재 시드와 패킷을 로깅해야 재부팅 후에도 방금 쏜 패킷이 무엇이었는지 블랙박스에 남아있게 됩니다.
        if (iteration % 10000 == 0) { // 로그 폭주 방지를 위해 1만 번 단위로 생존 신고
            logger.Log(L"FUZZ", std::format(L"Iteration {} running...", iteration));
        }

        // IOCTL 패킷 전송.
        bool result = driver.SendIoctl(TARGET_IOCTL_CODE, fuzzPayload, outputBuffer);

        if (!result) {
            // 드라이버가 뻗었거나 연결이 끊어짐 (크래시 확률 높음.)
            logger.Log(L"CRASH", std::format(L"IOCTL Failed at Iteration {}. Saving Seed...", iteration));
            logger.SaveCrashSeed(seed, fuzzPayload);
            break; // 발견 시 무한루프 탈출. (워커 종료)
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
    DWORD workerCount = min((max(1UL, coreCount / 2)), WinKernel::Constants::MAX_WORKERS);
    std::wcout << L"[+] Logical Cores: " << coreCount << L". Spawning " << workerCount << L" workers.\n";

    // 3. 자식 프로세스(워커) 생성
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    std::vector<WinKernel::Process::WorkerProcess> workers; // 아래 for문에서 생명주기를 관리하기 위한 백터. 각 worker process의 hProcess_(HANDLE)과 state_ 등등을 가지고 있습니다.

    for (DWORD i = 0; i < workerCount; ++i) {
        // 명령줄 인자 조합: 자기자신.exe --worker <ID> <SessionDir>     자식 프로세스를 만들 때마다 실행합니다.
        std::wstring cmdLine = std::format(L"\"{}\" --worker {} \"{}\"", exePath, i, sessionDir);

        WinKernel::Process::WorkerProcess worker; // move로 생명주기 안정성을 관리하기 위해 for문 바깥에 worker를 만들어줍니다.
        if (worker.Launch(i, cmdLine.c_str())) {
            std::wcout << L"  -> Worker " << i << L" launched successfully. (PID: " << worker.GetPID() << L")\n";
            // vector에 std::move를 통해 소유권 이동 (생명주기 안전성 보장) for문의 }를 만나는 순간 객체의 소멸자가 실행되어 마스터 프로세스와 소통할 주체인 worker가 사라지기 때문입니다.
            workers.push_back(std::move(worker));
        }
        else {
            std::wcout << L"  -> [!] Failed to launch Worker " << i << L"\n";
        }
    }

    std::wcout << L"[+] All workers are running. Press Ctrl+C to terminate.\n";

    // 4. 워커 프로세스 상태 모니터링 (Watchdog 패턴 적용)
    bool allFinished = false;
    std::vector<int> hangCounters(workers.size(), 0);

    while (!allFinished) {
        allFinished = true; // 일단 다 끝났다고 가정하고 검사 시작

        for (size_t i = 0; i < workers.size(); ++i) {  // workers 백터 안에 들어있는 내용물을 하나씩 꺼내서 worker라는 이름을 붙힙니다.
            // Process.ixx에서 작성한 GetState로 state를 조회하여 이미 완전히 종료(Finished)되었거나 죽은(Crashed) 워커는 건너뜀
            auto& worker = workers[i];
            if (worker.GetState() == WinKernel::Types::WorkerState::Finished ||
                worker.GetState() == WinKernel::Types::WorkerState::Crashed) {
                continue;
            }

            // 아직 안 끝난 워커가 하나라도 있다면 전체 루프는 계속 돌아야 함
            allFinished = false;

            // 1초(1000ms) 대기해 보기.
            // 수시로 감시하지만, 1초씩 감시하면 놓치는게 있는거 아닌가? 그 사이에 시도하는게 더 많은거 아닌가?
            // 감시 시도하다 "이미 끝난 시도다"같이 state를 얻습니다.  Hang같이 "이미 끝났다" 같은 보고를 받지 못하면 1초라는 단위가 먹히기 시작.
            if (!worker.Wait(1000)) {  // 1초 미만이라는 뜻이 아니라, 1초까지는 기다려 주겠다는 뜻입니다.
                // 1초가 지났는데도 안 끝났고 실행 중(Running) 상태인 경우.
                if (worker.IsRunning()) {   // '계속 실행중인 상태라면'을 가정합니다. 1초동안이나 실행중인 것 자체가 비정상적이기 때문.
                    hangCounters[i]++; // 응답 지연 카운터 1초 증가

                    // 만약 10초(10번) 이상 반응이 없다면 Hang(무한 루프)으로 판정
                    if (hangCounters[i] >= 10) {
                        std::wcout << L"[!] Warning: Worker " << worker.GetPID()
                            << L" is HANGING. Terminating process...\n";

                        // 강제 종료 후 상태를 Crashed로 유도
                        worker.Kill(1);
                    }
                }
            }
            else {
                // Wait가 true를 반환했다면 IsRunning으로 검사하는 1초 안에 작업을 끝내고 정상 종료된 것입니다.
                std::wcout << L"[+] Worker " << worker.GetPID() << L" finished.\n";
            }
        }
    }

    std::wcout << L"[+] Fuzzing session finished.\n";
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