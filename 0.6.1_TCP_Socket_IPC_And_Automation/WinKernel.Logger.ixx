module;
#include <Windows.h>
#include <string>
#include <vector>
#include <fstream> //  텍스트나 바이너리 파일을 읽고 쓰기 위한 C++ 파일 입출력(I/O) 표준 라이브러리.
#include <chrono>  //  현재 시간 확인이나 정밀한 시간 측정 등 시간과 관련된 연산을 처리하는 C++ 시간 표준 라이브러리입니다.
#include <format>

export module WinKernel.Logger;

export namespace WinKernel::Logger {

    class FuzzLogger {
    private:
        std::wstring sessionDirPath_;
        std::wstring logFilePath_;
        DWORD processId_;

        // 로그 내용에 들어갈 보기 편한 시간 포맷 (예: 2026-08-09 22:53:43)
        std::wstring GetLogTimestamp() {
            const auto now = std::chrono::system_clock::now();                                  // system_clock: 전 세계 표준시를 알려주는 컴퓨터의 메인 시계. now()는 한국 시간보다 9시간 느린 UTC 시간을 가져오게 됩니다.
            const auto local = std::chrono::zoned_time{ std::chrono::current_zone(), now };     // current_zone(): 현재 이 프로그램을 실행하고 있는 컴퓨터의 지역 설정을 알아내는 함수입니다. (KST, UTC+9라고 인지.)
            return std::format(L"{:%Y-%m-%d %H:%M:%S}", local);                                 // zoned_time: 위 2가지를 합쳐 우리가 보는 시간으로 변환해 주는 역할을 합니다.
        }

    public:
        // 마스터 프로세스가 세션 폴더명을 생성할 때 사용할 정적(static) 헬퍼 함수. ex) .\FuzzLogs_20260809_225343
        // 왜 static이냐? - 객체를 생성하지 않고도 함수를 호출하기 위해서입니다.
        /*
        1. C++에서는 일반(non-static)함수는 반드시 객체(인스턴스)를 생성한 뒤에만 호출할 수 있다는 규칙이 있습니다. 쓸데 없는 객체를 만드는 과정이 추가된다는 겁니다.
            예시) 만약 static을 제거한다면?
            1) 함수를 사용하려면 FuzzLogger 객체를 만들어야 함. 그런데 객체를 만드려면 폴더 경로를 넣어야 함.
            2) 그런데 그 폴더 경로를 얻고 싶어서 객체를 만드려고 하는 모순 발생.
            3) 그러기 위해서는 쓸데없는 객체를 만들어서 "객체 생성을 했다"는 규칙을 지키고 호출합니다. 그리고 일반 함수를 호출해야 합니다.

        2. GenerateSessionDirectoryName 함수는 폴더 이름을 만들 때 현재 시간만 사용하지 sessionPirPath_ 같은 객체의 상태(멤버 변수)를 사용하지 않습니다. (상태란 메모리. 즉, 현재 나의 메모리에 변경이 일어나지는 않는다.)
        */
        static std::wstring GenerateSessionDirectoryName(const std::wstring& prefix = L"C:\\Fuzz\\FuzzLogs_") {    // [Fix: UAC 우회] 로그도 표준권한 쓰기 보장 사용자 폴더에 기록 -> Host가 revert 전 pull로 수거
            const auto now = std::chrono::system_clock::now();
            const auto local = std::chrono::zoned_time{ std::chrono::current_zone(), now };

            // 폴더명에 사용할 수 없는 콜론(:) 등을 제외한 안전한 포맷을 지정. 윈도우는 폴더명에 콜론 사용을 제한하기 때문입니다.
            std::wstring folderName = std::format(L"{}{:%Y%m%d_%H%M%S}", prefix, local);
            CreateDirectoryW(L"C:\\Users\\joojo\\fuzzer_temp", NULL); // [Fix: UAC 우회] 세션 폴더 부모 루트 선(先)생성(사용자 프로필)
            CreateDirectoryW(folderName.c_str(), NULL);
            return folderName;
        }

        // 워커 프로세스는 마스터가 넘겨준 sessionDirPath를 그대로 받아서 사용
        FuzzLogger(DWORD processId, const std::wstring& sessionDirPath)
            // processId_에 processId 값을 넣어주는 것입니다. :를 사용하여 초기화 리스트로 값을 넣는 것이 컴퓨터 입장에서 훨씬 빠르고 효율적입니다.
            // 초기화 리스트는 이 함수에서 선언한 순서가 아니라, 클래스 맨 위에서 선언한 순서대로 만들어진다는 점을 유의해야 합니다.
            : processId_(processId), sessionDirPath_(sessionDirPath) {

            // 파일 생성. ex)Process_10244.log
            logFilePath_ = std::format(L"{}\\Process_{}.log", sessionDirPath_, processId_);
        }

        void Log(const std::wstring& level, const std::wstring& message) {
            // wofstream: w는 wide, o는 Output(쓰기)하는 것. 유니코드 문자열을 파일에 쓰기 위한 전용 도구.
            // std::ios - Input/Output Stream. C++에서 입출력과 관련된 옵션을 모아둔 그룹. ios::app은 append를 의미합니다. append를 하지 않는다면 로그를 기록할 때마다 파일 내용을 지우고 덮어씁니다.
            std::wofstream logFile(logFilePath_, std::ios::app);
            if (logFile.is_open()) {
                logFile << std::format(L"[{}] [{}] {}\n", GetLogTimestamp(), level, message);
            }
        }

        bool SaveCrashSeed(uint32_t seed, const std::vector<uint8_t>& mutatedBuffer) {
            std::wstring fileName = std::format(L"{}\\find_crash_Process{}_seed_{}.bin", // 퍼징으로 만들어낸 변조된 데이터는 사람의 눈으로 읽을 수 있는 텍스트가 아닌, 이진수입니다. 그러므로 bin으로 저장을 하는 것입니다.
                sessionDirPath_, processId_, seed);

            // ofstream: 위에서 설명한 wofstream에서 w가 빠졌습니다. 텍스트 인코딩을 신경쓰지 않고, 순수한 바이트 데이터나 일반 영문 텍스트를 파일에 쓸 때 사용하는 표준적 파일 쓰기 도구입니다.
            // crashFile은 객체입니다. fstream에서 파일을 다루기 위한 클래스를 미리 만들어놓았습니다. 어디에 지정한 함수인지 알아보기 어려워 주석을 남깁니다.
            // 어떤 파일을 어떤 방식으로 열 것인지를 지정한 것입니다.
            std::ofstream crashFile(fileName, std::ios::binary);
            if (!crashFile.is_open()) return false; // 없는 경로, 용량  부족, 백신으로 인한 차단 등의 이유로 생성에 실패한 경우를 상정합니다.

            // write(어디서부터, 얼만큼)
            // reinterpret_cast할 때 const char*로 하는가?  -> 완벽하게 복사하기 위한 표준 단위입니다.
            crashFile.write(reinterpret_cast<const char*>(mutatedBuffer.data()), mutatedBuffer.size());
            return true;
        }
    };
}