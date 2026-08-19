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

export namespace WinKernel::Worker {

    void Run(DWORD workerId, const std::wstring& sessionDir) {
        WinKernel::Logger::FuzzLogger logger(workerId, sessionDir);
        logger.Log(L"INFO", std::format(L"Worker {} started.", workerId));

        WinKernel::Driver::DriverController driver(WinKernel::Constants::TARGET_DRIVER_NAME);
        if (!driver.IsConnected()) {
            logger.Log(L"ERROR", L"Failed to connect to target driver. Exiting.");
            return;
        }
        logger.Log(L"INFO", L"Successfully connected to Driver.");

        uint32_t seed = std::random_device{}();
        WinKernel::Mutator::MutatorEngine mutator(seed);

        DWORD currentPid = GetCurrentProcessId();
        logger.Log(L"---", L"================================================================================");
        logger.Log(L"NEW_RUN", std::format(
            L"Worker {} Lifecycle Started | PID: {} | Seed: 0x{:08X} | Target IOCTL: 0x{:X}",
            workerId, currentPid, seed, WinKernel::Constants::TARGET_IOCTL_CODE
        ));
        logger.Log(L"---", L"================================================================================");

        std::vector<uint8_t> basePayload(WinKernel::Constants::DEFAULT_BUFFER_SIZE, 0x41);
        std::vector<uint8_t> outputBuffer(1024, 0x00);
         
        uint64_t iteration = 0;
        auto startTime = std::chrono::steady_clock::now();

        while (true) {
            iteration++;

            std::vector<uint8_t> fuzzPayload = basePayload;
            mutator.Mutate(fuzzPayload);

            if (iteration >= WinKernel::Constants::MAX_WORKER_ITERATIONS) {
                auto endTime = std::chrono::steady_clock::now();
                std::chrono::duration<double> elapsed = endTime - startTime;
                double execSpeed = iteration / elapsed.count();

                logger.Log(L"SUMMARY", std::format(
                    L"Worker {} completed {} iterations in {:.2f}s ({:.0f} exec/s). Recycling...",
                    workerId, iteration, elapsed.count(), execSpeed
                ));
                return;
            }

            bool result = driver.SendIoctl(WinKernel::Constants::TARGET_IOCTL_CODE, fuzzPayload, outputBuffer);

            if (!result) {
                logger.Log(L"CRASH", std::format(L"IOCTL Failed at Iteration {}. Saving Seed...", iteration));
                logger.SaveCrashSeed(seed, fuzzPayload);
                break;
            }
        }
    }
}