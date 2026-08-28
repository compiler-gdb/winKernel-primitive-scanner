module;
#include <Windows.h>
#include <string>
#include <vector>
#include <format>
#include <random>
#include <chrono>

export module WinKernel.Worker;

import WinKernel.Types;
import WinKernel.Logger;
import WinKernel.Mutator;
import WinKernel.Driver;
import WinKernel.IPC;

// [Fix: OS 레벨 예외(0xC0000005 등) 자가 흡수용 SEH 가드]
// SEH(__try/__except)는 객체 언와인딩이 필요한 함수(Run)와 같은 함수 내 공존 불가(C2712).
// 따라서 IOCTL 송신 위험 구간만 지역 소멸자 객체가 없는 별도 함수로 분리해 감싼다.
// 예외 발생 시 프로세스를 죽이지 않고 false + 예외 코드를 반환 -> 호출부가 continue로 자가 회복.
namespace WinKernel::Worker::detail {
    bool SendIoctlGuarded(
        WinKernel::Driver::DriverController& driver,
        DWORD ioctlCode,
        const std::vector<uint8_t>& payload,
        std::vector<uint8_t>& outputBuffer,
        DWORD& outExceptionCode) {
        outExceptionCode = 0;
        __try {
            return driver.SendIoctl(ioctlCode, payload, outputBuffer);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // 커널발 예외 코드(예: 0xC0000005) 포착 후 정상 반환 경로로 복귀 (프로세스 생존)
            outExceptionCode = GetExceptionCode();
            return false;
        }
    }
}

export namespace WinKernel::Worker {

    using WinKernel::IPC::WorkerPhase;

    // [TCP 전환] 워커는 초기화 시 호스트(monitoring.py TCP Server)에 접속하고, DeviceIoControl '직전'마다
    // 현재 시드/IOCTL 스냅샷을 send로 흘려보낸다. BSOD로 소켓이 끊기면 '마지막 InIoctl 패킷'이 곧 유죄 시드다.
    // [Design: 호스트 주도 결정론 스캔] useInjectedSeed=true면 난수 대신 injectedSeed를 그대로 사용하고,
    // startIoctlIdx부터 매트릭스를 시작한다 -> Host가 커서를 전진시켜 무한 재현 루프를 탈출.
    void Run(DWORD workerId, const std::wstring& sessionDir,
        bool useInjectedSeed = false, uint32_t injectedSeed = 0, size_t startIoctlIdx = 0,
        const std::wstring& reportHost = L"127.0.0.1",
        uint16_t reportPort = WinKernel::Constants::REPORT_PORT) {
        WinKernel::Logger::FuzzLogger logger(workerId, sessionDir);
        logger.Log(L"INFO", std::format(L"Worker {} started.", workerId));

        // [TCP 전환] 호스트 리스너 접속(RAII). 리포트 채널은 유죄 시드 귀속의 유일 경로이므로 필수 전제다.
        WinKernel::IPC::TcpReporter reporter;
        if (!reporter.Connect(reportHost, reportPort, workerId)) {
            // [Fix: 패킷 없는 BSOD 원천 차단] 리포트 채널 미연결 시 DeviceIoControl을 절대 쏘지 않고 안전 종료(미귀속 크래시 방지).
            logger.Log(L"ERROR", std::format(L"TCP connect failed (WSA err={}); refusing to fuzz without a report channel. Exiting.",
                reporter.LastError()));
            reporter.Close();
            return;
        }
        logger.Log(L"INFO", std::format(L"TCP report channel connected -> {}:{}.", reportHost, reportPort));
        reporter.Report(WorkerPhase::Init, 0, 0, 0, 0, 0, 0, nullptr, 0);

        WinKernel::Driver::DriverController driver(WinKernel::Constants::TARGET_DRIVER_NAME);
        if (!driver.IsConnected()) {
            logger.Log(L"ERROR", L"Failed to connect to target driver. Exiting.");
            reporter.Close();
            return;
        }
        logger.Log(L"INFO", L"Successfully connected to Driver.");

        // [Design: 결정론 시드] Host가 주입한 시드가 있으면 재현 가능하도록 그대로 사용, 없으면 레거시 난수 경로
        uint32_t seed = useInjectedSeed ? injectedSeed : std::random_device{}();
        WinKernel::Mutator::MutatorEngine mutator(seed);

        DWORD currentPid = GetCurrentProcessId();
        logger.Log(L"---", L"================================================================================");
        logger.Log(L"NEW_RUN", std::format(
            L"Worker {} Lifecycle Started | PID: {} | Seed: 0x{:08X} | Target IOCTL: 0x{:X}",
            workerId, currentPid, seed, WinKernel::Constants::TARGET_IOCTL_CODE
        ));
        logger.Log(L"---", L"================================================================================");

        std::vector<uint8_t> outputBuffer(1024, 0x00);

        uint64_t iteration = 0;
        uint64_t sehAbsorbed = 0; // [Fix: 자가 흡수한 OS 예외 누적 카운터(핫패스 로그 스로틀용)]
        // [Fix: 유저 모드 흡수 예외 중복 리포트 억제] 이미 Crashed로 통지한 (IOCTL<<32|Seed) 키 (호스트 덤프 중복 방지)
        std::vector<uint64_t> sehReportedKeys;
        auto startTime = std::chrono::steady_clock::now();

        // [Design: 호스트 주도 시작점] 첫 패스만 startIoctlIdx부터, 이후 패스는 전 범위 순회 (범위 밖이면 0으로 보정)
        size_t startIdx = (startIoctlIdx < WinKernel::Constants::TARGET_IOCTL_COUNT) ? startIoctlIdx : 0;
        bool firstPass = true;

        // [Fix: 가변 크기 이스케일레이션 제거] 모든 페이로드를 DEFAULT_BUFFER_SIZE(4096, PAGE_SIZE)로 고정해 드라이버를 직격.
        constexpr uint32_t fixedSize = WinKernel::Constants::DEFAULT_BUFFER_SIZE;
        const std::vector<uint8_t> basePayload(fixedSize, 0x41);

        while (true) {
            const size_t beginIdx = firstPass ? startIdx : 0;
            firstPass = false;
            for (size_t ioctlIdx = beginIdx; ioctlIdx < WinKernel::Constants::TARGET_IOCTL_COUNT; ++ioctlIdx) {
                const DWORD ioctlCode = WinKernel::Constants::TARGET_IOCTL_CODES[ioctlIdx];

                for (uint32_t rep = 0; rep < WinKernel::Constants::ITERATIONS_PER_PROFILE; ++rep) {
                    iteration++;

                    if (iteration >= WinKernel::Constants::MAX_WORKER_ITERATIONS) {
                        auto endTime = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = endTime - startTime;
                        double execSpeed = iteration / elapsed.count();

                        // [TCP 전환] 정상 완주를 호스트가 유죄로 오탐하지 않도록 Completed 통지 후 소켓 정상 종료(FIN).
                        reporter.Report(WorkerPhase::Completed, ioctlCode, seed,
                            fixedSize, fixedSize, iteration, 0, nullptr, 0);

                        logger.Log(L"SUMMARY", std::format(
                            L"Worker {} completed {} iterations in {:.2f}s ({:.0f} exec/s). Recycling...",
                            workerId, iteration, elapsed.count(), execSpeed
                        ));
                        reporter.Close();
                        return;
                    }

                    std::vector<uint8_t> fuzzPayload = basePayload;
                    mutator.Mutate(fuzzPayload); // 4096바이트 고정 버퍼 내부 콘텐츠만 변조 (크기는 불변)

                    // [TCP 전환: 유죄 후보 사전 스냅샷] 커널 진입 '직전' InIoctl 패킷을 호스트 RAM으로 직접 스트리밍.
                    // 디스크/HGFS 경유가 없으므로, BSOD로 소켓이 끊기면 이 마지막 패킷이 그대로 유죄 근거가 된다.
                    reporter.Report(WorkerPhase::InIoctl, ioctlCode, seed,
                        fixedSize, fixedSize, iteration, 0,
                        fuzzPayload.data(), static_cast<uint32_t>(fuzzPayload.size()));

                    // [Fix: 패킷 없는 BSOD 원천 차단] InIoctl 스냅샷 송신이 실패(소켓 절단)했다면 이 IOCTL은 호스트에
                    //  귀속 근거가 없다 -> 커널 진입을 포기하고 안전 종료(마스터 respawn이 재접속을 시도).
                    if (!reporter.Valid()) {
                        logger.Log(L"WARN", std::format(
                            L"InIoctl report failed (WSA err={}); skipping DeviceIoControl to avoid unattributed BSOD. Exiting.",
                            reporter.LastError()));
                        reporter.Close();
                        return;
                    }

                    // [Fix: OS 레벨 예외 자가 흡수] SEH 가드 경유로 송신 -> 커널발 AV(0xC0000005)에도 워커 생존
                    DWORD sehCode = 0;
                    bool result = detail::SendIoctlGuarded(driver, ioctlCode, fuzzPayload, outputBuffer, sehCode);

                    if (sehCode != 0) {
                        // [Fix: 예외 시 종료(return/break) 금지] 실제 예외(0xC0000005 등)를 유죄로 처리 후 continue로 자가 회복
                        ++sehAbsorbed;

                        // [TCP 전환: 유저모드 흡수 예외 통지] 동일 (IOCTL, Seed)는 워커 생애당 1회만 Crashed 리포트
                        // -> 호스트가 BSOD(소켓 절단)와 유저모드 AV(소켓 유지)를 구분해 중복 없이 .bin 영구화.
                        const uint64_t sehKey = (static_cast<uint64_t>(ioctlCode) << 32) | seed;
                        bool sehAlready = false;
                        for (uint64_t k : sehReportedKeys) { if (k == sehKey) { sehAlready = true; break; } }
                        if (!sehAlready) {
                            reporter.Report(WorkerPhase::Crashed, ioctlCode, seed,
                                fixedSize, fixedSize, iteration, sehCode,
                                fuzzPayload.data(), static_cast<uint32_t>(fuzzPayload.size()));
                            sehReportedKeys.push_back(sehKey);
                        }

                        // [Fix: 핫패스 로그 폭주 방지] 첫 예외와 이후 1000회마다만 기록
                        if (sehAbsorbed == 1 || (sehAbsorbed % 1000) == 0) {
                            logger.Log(L"SEH", std::format(
                                L"OS exception 0x{:08X} absorbed (#{}) | IOCTL 0x{:X} Seed 0x{:08X} size {} iter {} -> continue",
                                sehCode, sehAbsorbed, ioctlCode, seed, fixedSize, iteration));
                        }
                        continue; // 안쪽 for(rep) 다음 반복으로 -> 프로세스 종료 없이 연속 퍼징(자가 회복)
                    }

                    // [Design: 오탐 덤프 폭증 방지] 단순 DeviceIoControl 거부(양성)는 다음 케이스로 진행만 하고 통지 안 함.
                    // 실제 커널 예외(0xC0000005)/BSOD는 예외 흡수/소켓 절단으로 나타나 호스트가 .bin 덤프를 전담한다.
                    (void)result;
                }
            }
        }
    }
}
