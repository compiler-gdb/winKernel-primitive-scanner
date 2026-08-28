#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>

import WinKernel.Manager;
import WinKernel.Worker;
import WinKernel.Types;

// [TCP 전환] 호스트 리포트 엔드포인트(--report-host/--report-port)를 워커/마스터 양쪽에서 공통 파싱.
int wmain(int argc, wchar_t* argv[]) {
    // 0. 로케일 설정 안전 래핑 (POSIX "ko_KR.UTF-8" 에러로 인한 즉시 크래시 방지)
    try {
        std::locale::global(std::locale(""));
        std::wcout.imbue(std::locale());
        std::wcerr.imbue(std::locale());
    }
    catch (...) {
        // 실패 시 기본 시스템 로케일 유지
    }

    try {
        std::wstring reportHost = L"127.0.0.1";
        uint16_t reportPort = WinKernel::Constants::REPORT_PORT;

        // 1. 워커 모드 분기 (인자가 --worker 인 경우)
        // 형식: --worker <id> <sessionDir> [0xSEED <startIoctlIdx>] [--report-host <h>] [--report-port <p>]
        if (argc >= 4 && std::wstring(argv[1]) == L"--worker") {
            DWORD workerId = static_cast<DWORD>(std::wcstoul(argv[2], nullptr, 10));
            std::wstring sessionDir = argv[3];

            bool useInjectedSeed = false;
            uint32_t injectedSeed = 0;
            size_t startIoctlIdx = 0;
            int positional = 0;

            // [수정] IOCTL/크기 CLI 개방: --ioctl 는 반복 지정 가능(목록 구성), --min-size/--max-size 로 가변 크기 범위 지정.
            std::vector<DWORD> ioctlOverride;
            uint32_t minSize = WinKernel::Constants::MIN_PAYLOAD_SIZE;
            uint32_t maxSize = WinKernel::Constants::MAX_PAYLOAD_SIZE;
            bool ioctlRandom = false; // [수정] opt-in 구조적 랜덤 IOCTL 모드

            for (int i = 4; i < argc; ++i) {
                const std::wstring a = argv[i];
                if (a == L"--report-host" && (i + 1) < argc) {
                    reportHost = argv[++i];
                } else if (a == L"--report-port" && (i + 1) < argc) {
                    reportPort = static_cast<uint16_t>(std::wcstoul(argv[++i], nullptr, 0));
                } else if (a == L"--ioctl" && (i + 1) < argc) {
                    ioctlOverride.push_back(static_cast<DWORD>(std::wcstoul(argv[++i], nullptr, 0))); // 0x 접두사 자동 인식
                } else if (a == L"--ioctl-random") {
                    ioctlRandom = true;
                } else if (a == L"--min-size" && (i + 1) < argc) {
                    minSize = static_cast<uint32_t>(std::wcstoul(argv[++i], nullptr, 0));
                } else if (a == L"--max-size" && (i + 1) < argc) {
                    maxSize = static_cast<uint32_t>(std::wcstoul(argv[++i], nullptr, 0));
                } else if (positional == 0) {
                    injectedSeed = static_cast<uint32_t>(std::wcstoul(a.c_str(), nullptr, 0)); // 0x 접두사 자동 인식
                    useInjectedSeed = true;
                    positional = 1;
                } else if (positional == 1) {
                    startIoctlIdx = static_cast<size_t>(std::wcstoul(a.c_str(), nullptr, 10));
                    positional = 2;
                }
            }

            WinKernel::Worker::Run(workerId, sessionDir, useInjectedSeed, injectedSeed, startIoctlIdx,
                reportHost, reportPort, ioctlOverride, minSize, maxSize, ioctlRandom);
            return 0;
        }

        // 2. 마스터 모드 진입
        uint32_t baseSeed = 0;
        bool baseSeedProvided = false;
        size_t startIoctlIdx = 0;
        int positional = 0;

        // [수정] 마스터도 워커와 동일하게 IOCTL/크기 CLI 를 수용해 자식 워커 커맨드라인에 전파한다.
        std::vector<DWORD> ioctlOverride;
        uint32_t minSize = WinKernel::Constants::MIN_PAYLOAD_SIZE;
        uint32_t maxSize = WinKernel::Constants::MAX_PAYLOAD_SIZE;
        bool ioctlRandom = false; // [수정] opt-in 구조적 랜덤 IOCTL 모드

        for (int i = 1; i < argc; ++i) {
            const std::wstring a = argv[i];
            if (a == L"--base-seed" && (i + 1) < argc) {
                baseSeed = static_cast<uint32_t>(std::wcstoul(argv[++i], nullptr, 0));
                baseSeedProvided = true;
            } else if (a == L"--start-ioctl" && (i + 1) < argc) {
                startIoctlIdx = static_cast<size_t>(std::wcstoul(argv[++i], nullptr, 10));
            } else if (a == L"--report-host" && (i + 1) < argc) {
                reportHost = argv[++i];
            } else if (a == L"--report-port" && (i + 1) < argc) {
                reportPort = static_cast<uint16_t>(std::wcstoul(argv[++i], nullptr, 0));
            } else if (a == L"--ioctl" && (i + 1) < argc) {
                ioctlOverride.push_back(static_cast<DWORD>(std::wcstoul(argv[++i], nullptr, 0)));
            } else if (a == L"--ioctl-random") {
                ioctlRandom = true;
            } else if (a == L"--min-size" && (i + 1) < argc) {
                minSize = static_cast<uint32_t>(std::wcstoul(argv[++i], nullptr, 0));
            } else if (a == L"--max-size" && (i + 1) < argc) {
                maxSize = static_cast<uint32_t>(std::wcstoul(argv[++i], nullptr, 0));
            } else {
                switch (positional++) {
                case 0: reportHost = a; break;                                            // argv[1] = 호스트 IP
                case 1: reportPort = static_cast<uint16_t>(std::wcstoul(a.c_str(), nullptr, 0)); break; // 포트
                case 2: baseSeed = static_cast<uint32_t>(std::wcstoul(a.c_str(), nullptr, 0)); baseSeedProvided = true; break; // 0xSEED
                case 3: startIoctlIdx = static_cast<size_t>(std::wcstoul(a.c_str(), nullptr, 10)); break; // 시작 IOCTL 인덱스
                default: break;
                }
            }
        }

        if (reportHost == L"127.0.0.1") {
            std::wcerr << L"[!] WARNING: report-host not supplied; falling back to 127.0.0.1. "
                        L"Crash seeds will NOT reach the host listener. "
                        L"Pass `<hostIp> <port> <0xSEED> <startIoctl>` or `--report-host <ip>`.\n";
        }

        WinKernel::Manager::MasterController master;
        return master.Run(baseSeed, baseSeedProvided, startIoctlIdx, reportHost, reportPort,
            ioctlOverride, minSize, maxSize, ioctlRandom);

    }
    catch (const std::exception& e) {
        std::wcerr << L"[FATAL] Standard exception in main: " << e.what() << std::endl;
        return 99;
    }
    catch (...) {
        std::wcerr << L"[FATAL] Unknown exception in main." << std::endl;
        return 98;
    }
}