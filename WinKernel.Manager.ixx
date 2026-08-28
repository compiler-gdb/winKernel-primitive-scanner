module;
#include <Windows.h>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <thread>
#include <memory>
#include <optional>
#include <iostream>
#include <format>

export module WinKernel.Manager;

import WinKernel.Process;
import WinKernel.Types;
import WinKernel.Driver;
import WinKernel.System;
import WinKernel.Logger;

export namespace WinKernel::Manager {
	//template은 컴파일러에게 자료형은 나중에 정할테니 일단 구조대로 동작하게 하라는 것입니다. (자료형에 얽매이지 않고 재사용 가능한 코드를 만들기 위한 틀)
	//typename T에서 T는 특정 자료형을 T라는 기호라고 사용하겠다며 컴파일러에게 알려줍니다. typename T에서 T는 그냥 임의로 개발자가 정하는 이름입니다. 
	template <typename T> 
	class TaskQueue {
	private:
		//std::queue<T>는 T라는 자료형의 데이터를 저장하는 queue라는 의미입니다. 만약 TaskQueue<int>로 사용하면 queue<T>는 std::queue<int> 처럼 정수를 담는 큐가 됩니다.
		std::queue<T> queue_;

		//mutable은 변할 수 있다는 것을 의미합니다. const 함수 안에서도 이 변수 만큼은 수정할 수 있게 해달라는 것입니다.
		//std::mutex는 int가 숫자를 담듯이 자물쇠의 상태를 담는 C++ 객체입니다. .lock()과 .unlock()이라는 동작을 가집니다.
		mutable std::mutex mutex_;

		//condition_variable은 조건 변수라는 뜻입니다. 멀티스레드 환경에서 스레드끼리 신호를 주고받으며 대기/깨어남을 조율하며 동기화하는 도구입니다.
		std::condition_variable cv_;
		bool stopFlag_{ false };
	
	//Thread-Safe Task Queue
	public:
		TaskQueue() = default;
		~TaskQueue() { Clear(); }

		//복사 및 이동 방지를 합니다. 스레드 동기화 객체 안전성을 확보합니다.

		//복사 생성자를 금지합니다.
		//생성자 안에 클래스와 같은 타입의 객체 원본을 읽기 전용으로 참조할 경우, 다시 말해 기존 객체를 복사해서 새 객체를 만들때를 의미합니다.
		TaskQueue(const TaskQueue&) = delete;
		//operator는 이미 만들어진 객체에 다른 객체의 값을 대입할 때 호출되는 함수입니다.
		//operator=는 = 연산자 우변에 들어올 값으로 TaskQueue 타입의 객체를 받겠다는 의미입니다. opertator+, operator<< 등도 가능합니다.
		//
		//operator 우변에 const TaskQueue&처럼 참조 형식으로 만든 이유는 불필요한 복사 없이 값을 보는 것입니다. 특히, 값이 매우 크거나 mutex 같이 복사 불가능한 멤버가 있다면 문제가 발생합니다.
		//반환 타입(TaskQueue*)에 &를 붙힌 이유는 자기 자신을 반환할 때 또 다시 자기 자신을 복사한 임시 객체를 만들지 않기 위함입니다.
		//operator는 같은 타입을 검사한다고 했습니다. 우변에 TaskQueue라고 되어있다면 자연스럽게 좌측도 TaskQueue로 인식합니다.
		//
		//delete는 이 함수는 만들지도 말고, 누가 쓰려고 하면 컴파일 에러를 내라고 컴파일러에게 명령하는 것입니다.
		//mutex나 condition_variable 같은 것들은 복사가 불가능하기 때문에 TaskQueue끼리는 복사하지 못하게 합니다.
		TaskQueue& operator=(const TaskQueue&) = delete;

		//작업을 추가합니다.
		void Push(T item) {
			{
				// std::lock_guard는 클래스 템플릿(타입), <std::mutex>는 lock_guard가 어떤 타입의 자물쇠를 관리할지 결정하는 템플릿 인자, lock은 객체 이름, (mutex_)는 생성자 인자로 실제 잠글 자물쇠입니다.
				std::lock_guard<std::mutex> lock(mutex_);
				//push(item)을 하면 item의 데이터를 큐 내부에 복사하는 비용이 발생하지만 move를 이용하면 item의 힙 메모리 포인터나 문자열 버퍼의 주소만 큐 내부로 넘깁니다.
				queue_.push(std::move(item));
			}//괄호를 벗어나면 자물쇠가 풀립니다.
			//notify_one(): 자고 있는 스레드 중 하나만 깨우라는 신호를 줍니다.
			cv_.notify_one();
		}

		//작업을 꺼냅니다. 데이터가 올 때까지 대기(Blocking)
		std::optional<T> Pop() {
			std::unique_lock<std::mutex> lock(mutex_);

			//큐에 데이터가 생기거나, 종료 신호가 올 때까지 스레드를 재웁니다.
			cv_.wait(lock, [this]() {			// [this]() {...} 는 람다함수입니다. TaskQueue 객체가 자기 자신의 포인터를 람다 함수 안으로 넘겨주어 람다 함수에서도 클래스 멤버 변수에 접근할 수 있습니다.
				return !queue_.empty() || stopFlag_;
			});

			//께어났는데 종료 신호가 왔고 큐도 비어있다면 데이터가 없음을 반환합니다.
			if (stopFlag_ && queue_.empty()) {
				return std::nullopt;			//비어 있음을 의미합니다.
			}
			// 맨 앞 데이터를 꺼내서 반환합니다.
			T item = std::move(queue_.front()); //맨 앞 데이터의 소유권을 가져옵니다.
			queue_.pop();						//큐에서 맨 앞 칸을 지웁니다. 이를 위해서 소유권이 필요했습니다.
			return item;
		}
		/*
		std::lock_guard
		단순 스코프{} 단위 잠금, lock/unlock 수동제어 불가, condition_variable.wait() 불가, 즉시 잠금. 지연 잠금 불가, 소유권 이동 불가, 오버헤드 0.

		std::unique_lock
		중간 해제/조건 대기 등 복잡한 잠금 제어, 수동 lock/unlock 가능, condition_variable.wait() 가능, 지연 잠금 가능, 락 소유권 이동 가능, 미세한 오버헤드.
		*/

		//작업 큐 중지 및 대기 해제
		void Stop() {
			{
				std::lock_guard<std::mutex> lock(mutex_);
				stopFlag_ = true;
			}
			cv_.notify_all();
		}
		
		void Clear() {
			std::lock_guard<std::mutex> lock(mutex_);
			std::queue<T> emptyQueue;
			std::swap(queue_, emptyQueue);
		}
		
		size_t Size() const {
			//읽기 전용 함수지만, lock(mutex_)를 실행하는 순간 metex 내부의 상태가 열림에서 잠김으로 변합니다. 컴파일러는 읽기 전용인데 변수를 수정했다고 판단하여 에러를 발생시킵니다.
			//그러므로 위에서 mutex_에 mutable을 붙혀서 선언했습니다.
			std::lock_guard<std::mutex> lock(mutex_);
			return queue_.size();
		}

		bool IsEmpty() const {
			std::lock_guard<std::mutex> lock(mutex_);
			return queue_.empty();
		}
	};

	//WorkerManager
	class WorkerManager {
	private:
		//std::vector는 크기가 고정되지 않고 자유롭게 줄거나 늘어날 수 있습니다.
		//WinKernel::Process::WorkerProcess는 WinKernel.Process에서 가져온 윈도우 자식 프로세스 1개를 제어하는 객체입니다.
		std::vector<WinKernel::Process::WorkerProcess> workers_;
		DWORD maxWorkers_{ 0 };
	
	public:
		// 기본 생성자: 사용 가능한 H/W 논리 코어 수 감지
		WorkerManager() {
			// [수정] hardware_concurrency()가 2 이하일 때 unsigned 뺄셈 언더플로우(거대한 양수)를 방지
			unsigned int hc = std::thread::hardware_concurrency();
			unsigned int cores = (hc > 2) ? (hc - 2) : 0;

			//(cores>0) ? A:B 
			//조건식 ? 참일 때 값 : 거짓일 때 값
			//:4 예외 처리용 기본값. hardware_concurrency()가 코어 수 감지에 실패 시 0을 반환할 수 있습니다.
			//static_cast: 컴파일 타임에 상식적으로 이 변환이 가능한가를 검사하고 변환.
			maxWorkers_ = (cores > 0) ? static_cast<DWORD>(cores) : 4;
		}

		explicit WorkerManager(DWORD customWorkerCount) //explicit: 암시적으로 형변환을 하지 말고 개발자가 명시적으로 직접 적었을 때만 변환하라고 강제합니다.
			//WorkerManager wm = 4; -> 컴파일 에러. WorkerManager wm(4); 또는 WorkerManager wm = WorkerManager(4); 형태로 명시적 생성해야 합니다.
			: maxWorkers_(customWorkerCount) {
		}

		~WorkerManager() {
			StopAll();
		}

		//복사 방지
		WorkerManager(const WorkerManager&) = delete;
		WorkerManager& operator=(const WorkerManager&) = delete;

		//이동 허용 -> 복사 생성자를 =delete하면 컴파일러는 기본 이동 생성자를 자동 생성하지 않고 차단하기에 굳이 작성하는 것입니다.
		//&&는 우측값 참조입니다. =default는 컴파일러가 알아서 이동 코드를 만들라는 의미입니다.
		//noexcept는 이동하다가 예외처리를 하지 않음을 보장합니다.
		WorkerManager(WorkerManager&&) noexcept = default;
		WorkerManager& operator=(WorkerManager&&) noexcept = default;

		//지정된 개수만큼 워커 프로세스 일괄 실행
		bool InitializeAndLaunchAll(const wchar_t* targetBinaryPath) {
			workers_.clear();
			workers_.reserve(maxWorkers_);

			for (DWORD i = 0; i < maxWorkers_; ++i) {
				WinKernel::Process::WorkerProcess worker;

				if (worker.Launch(i + 1, targetBinaryPath)) {
					workers_.push_back(std::move(worker));
				}
				else {
					//일부 생성 실패 시 현재까지 실행된 것 정리 후 반환
					StopAll();
					return false;
				}
			}
			return true;
		}

		// 모든 워커 프로세스 즉시 종료 및 자원 정리
		void StopAll() {
			for (auto& worker : workers_) {
				if (worker.IsRunning()) {
					worker.Kill(0);
				}
				worker.Close();
			}
			workers_.clear();
		}

		//살아있는 워커 수 반환
		size_t GetActiveWorkerCount() const {
			size_t activeCount = 0;
			for (const auto& worker : workers_) {
				if (worker.IsRunning()) {
					activeCount++;
				}
			}
			return activeCount;
		}

		//특정 워커 상태 점검
		size_t GetTotalWorkerCount() const { return workers_.size(); }
		DWORD GetMaxWorkerLimit() const { return maxWorkers_; }

		//워커 백터 참조
		std::vector<WinKernel::Process::WorkerProcess>& GetWorkers() { return workers_; }
	};

	class MasterController {
	public:
		// [Design: 호스트 주도 커서 수신] baseSeedProvided=true면 워커별 결정론 시드(base+workerId)를 주입하고
		// startIoctlIdx부터 스캔시킨다. 미제공(레거시) 시 워커는 난수/0으로 기존 동작을 유지한다.
		// [TCP 전환] reportHost/reportPort는 각 워커가 접속할 호스트 TCP 리스너(monitoring.py) 주소.
		int Run(uint32_t baseSeed = 0, bool baseSeedProvided = false, size_t startIoctlIdx = 0,
			const std::wstring& reportHost = L"127.0.0.1",
			uint16_t reportPort = WinKernel::Constants::REPORT_PORT,
			// [수정] IOCTL/크기 CLI 를 자식 워커 커맨드라인으로 전파. 비어있으면 워커가 내장 기본값을 사용.
			const std::vector<DWORD>& ioctlOverride = {},
			uint32_t minSize = WinKernel::Constants::MIN_PAYLOAD_SIZE,
			uint32_t maxSize = WinKernel::Constants::MAX_PAYLOAD_SIZE,
			bool ioctlRandom = false) {
			baseSeed_ = baseSeed;
			baseSeedProvided_ = baseSeedProvided;
			startIoctlIdx_ = startIoctlIdx;
			reportHost_ = reportHost;
			reportPort_ = reportPort;
			ioctlOverride_ = ioctlOverride;
			minSize_ = minSize;
			maxSize_ = maxSize;
			ioctlRandom_ = ioctlRandom;
			std::wcout << std::format(L"[+] TCP report endpoint for workers: {}:{}\n", reportHost_, reportPort_);
			if (baseSeedProvided_) {
				std::wcout << std::format(L"[+] Host-driven deterministic scan: base-seed 0x{:08X}, start-ioctl {}\n",
					baseSeed_, startIoctlIdx_);
			}

			std::wcout << L"[+] Starting WinKernel Fuzzer Master Controller...\n";
			// [Diag: 권한 베이스라인] 성공/실패 무관하게 상승 여부를 콘솔 로그에 남겨 드라이버 오픈 실패(err5) 원인 분리에 사용
			std::wcerr << std::format(L"[BOOT] Master pid={} elevated={}\n",
				GetCurrentProcessId(), IsProcessElevated() ? 1 : 0);

			// 1. 사전 검사 (Pre-Flight Check)
			std::wcout << L"[*] Checking target driver availability...\n";
			{
				WinKernel::Driver::DriverController preflightCheck(WinKernel::Constants::TARGET_DRIVER_NAME);
				if (!preflightCheck.IsConnected()) {
					// [Diag: rc=1 원인 확정] 드라이버 오픈 실패 코드/권한을 stderr로 즉시 출력 -> 게스트 콘솔 리다이렉트로 Host가 pull.
					const DWORD derr = preflightCheck.LastError();
					std::wcerr << std::format(
						L"[FATAL] Driver open failed. device=\\\\.\\{} GetLastError={} ({}) elevated={}\n",
						WinKernel::Constants::TARGET_DRIVER_NAME, derr,
						(derr == ERROR_FILE_NOT_FOUND ? L"driver NOT loaded" :
						 derr == ERROR_ACCESS_DENIED  ? L"ACCESS DENIED (needs admin/elevation)" : L"other"),
						IsProcessElevated() ? 1 : 0);
					std::wcout << L"\n[FATAL ERROR] Cannot connect to target driver.\n"
						<< L"[!] Ensure the driver is loaded before starting the fuzzer.\n"
						<< L"[!] Master process aborted.\n";
					return 1;
				}
			}
			std::wcout << L"[+] Target driver connected successfully.\n";

			// 2. 세션 디렉토리 생성
			std::wstring sessionDir = WinKernel::Logger::FuzzLogger::GenerateSessionDirectoryName();
			if (GetFileAttributesW(sessionDir.c_str()) == INVALID_FILE_ATTRIBUTES) {
				// [Diag: 디렉터리 생성 실패 국소화] 세션 로그 폴더 생성 실패 시 GetLastError 출력 (퍼징은 계속: best-effort)
				std::wcerr << std::format(L"[WARN] Session dir NOT created: {} GetLastError={}\n",
					sessionDir, GetLastError());
			}
			std::wcout << L"[+] Session Directory Created: " << sessionDir << L"\n";

			// 3. 코어 수 계산 및 워커 생성
			DWORD coreCount = WinKernel::System::GetLogicalCoreCount();
			// [수정] coreCount가 2 이하일 때 DWORD(unsigned) 뺄셈 언더플로우를 삼항 연산자로 원천 차단
			DWORD reservedCores = (coreCount > 2) ? (coreCount - 2) : 1;
			DWORD workerCount = min(max(1UL, reservedCores), WinKernel::Constants::MAX_WORKERS);
			std::wcout << L"[+] Logical Cores: " << coreCount << L". Spawning " << workerCount << L" workers.\n";

			// [TCP 전환] 공유 메모리(SHM) 사전 체크포인트 파이프라인은 폐기했다.
			// 유죄 시드는 각 워커가 IOCTL 직전에 호스트 TCP 리스너로 직접 send하고, 호스트가 소켓 절단으로 판정한다.
			wchar_t exePath[MAX_PATH];
			GetModuleFileNameW(NULL, exePath, MAX_PATH);

			for (DWORD i = 0; i < workerCount; ++i) {
				// [TCP 전환] 커맨드라인 말미에 결정론 시드/시작 IOCTL + 호스트 리포트 주소를 전달
				std::wstring cmdLine = BuildWorkerCmdLine(exePath, i, sessionDir);
				WinKernel::Process::WorkerProcess worker;

				if (worker.Launch(i, cmdLine.c_str())) {
					workers_.push_back(std::move(worker));
				}
			}

			std::wcout << L"[+] All workers are running. Press Ctrl+C to terminate.\n";
			MonitorLoop(exePath, sessionDir);
			return 0;
		}

	private:
		std::vector<WinKernel::Process::WorkerProcess> workers_;

		// [Design: 호스트 주도 결정론 커서] Host가 주입한 시드/시작 IOCTL. 초기 스폰·respawn 모두 동일 규칙 적용.
		uint32_t baseSeed_{ 0 };
		bool baseSeedProvided_{ false };
		size_t startIoctlIdx_{ 0 };

		// [TCP 전환] 워커가 접속할 호스트 리스너(monitoring.py) 주소. 스폰/respawn 커맨드라인에 부착된다.
		std::wstring reportHost_{ L"127.0.0.1" };
		uint16_t reportPort_{ WinKernel::Constants::REPORT_PORT };

		// [수정] 자식 워커에 전파할 IOCTL 목록/가변 크기 범위. 비어있으면 워커가 내장 기본값을 사용.
		std::vector<DWORD> ioctlOverride_{};
		uint32_t minSize_{ WinKernel::Constants::MIN_PAYLOAD_SIZE };
		uint32_t maxSize_{ WinKernel::Constants::MAX_PAYLOAD_SIZE };
		bool ioctlRandom_{ false }; // [수정] 구조적 랜덤 IOCTL 모드 전파 여부

		// [Diag: 권한 진단] 현재 프로세스가 상승(관리자) 토큰인지. 드라이버 오픈 실패(err5)와 미로드(err2) 분리에 사용.
		static bool IsProcessElevated() {
			HANDLE tok = nullptr;
			TOKEN_ELEVATION el{};
			DWORD sz = 0;
			bool elevated = false;
			if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
				if (GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &sz)) {
					elevated = (el.TokenIsElevated != 0);
				}
				CloseHandle(tok);
			}
			return elevated;
		}

		// [Design: 워커 커맨드라인 단일 생성점] 결정론 모드면 워커별 시드(base+id)+시작 IOCTL을 positional로 부착하고,
		// 이어서 호스트 리포트 주소(host port)를 붙인다. 미제공(레거시) 시엔 리포트 주소만 붙여 난수 경로로 동작.
		// 형식: --worker <id> "<sessionDir>" [0xSEED <startIoctl>] --report-host <h> --report-port <p>
		std::wstring BuildWorkerCmdLine(const wchar_t* exePath, DWORD workerId,
			const std::wstring& sessionDir) const {
			// [수정] IOCTL 목록/크기 범위를 커맨드라인 말미 공통 플래그로 부착(결정론/레거시 경로 공통).
			std::wstring extra;
			for (DWORD code : ioctlOverride_) {
				extra += std::format(L" --ioctl 0x{:X}", code);
			}
			extra += std::format(L" --min-size {} --max-size {}", minSize_, maxSize_);
			if (ioctlRandom_) {
				extra += L" --ioctl-random";
			}

			if (baseSeedProvided_) {
				const uint32_t seed = baseSeed_ + workerId; // 워커 간 시드 충돌 없이 재현 가능
				return std::format(L"\"{}\" --worker {} \"{}\" 0x{:08X} {} --report-host {} --report-port {}{}",
					exePath, workerId, sessionDir, seed, startIoctlIdx_, reportHost_, reportPort_, extra);
			}
			return std::format(L"\"{}\" --worker {} \"{}\" --report-host {} --report-port {}{}",
				exePath, workerId, sessionDir, reportHost_, reportPort_, extra);
		}

		// [TCP 전환] 모니터는 유죄 판정/영구화를 더 이상 하지 않는다(호스트가 소켓 절단+Crashed 리포트로 전담).
		// 마스터의 역할은 (1) 죽은 워커 즉시 respawn, (2) CPU 진척 0인 커널 데드락 워커만 사살로 축소된다.
		void MonitorLoop(const wchar_t* exePath, const std::wstring& sessionDir) {
			std::vector<int> hangCounters(workers_.size(), 0);
			// [추가] 워커별 이전 CPU 사용량 기록
			std::vector<ULONGLONG> lastCpuTimes(workers_.size(), 0);

			// 전역 폭주 카운터 (진단용 경고에만 사용, 마스터 자폭 트리거는 폐기)
			int globalRapidDeathCount = 0;
			ULONGLONG lastWindowTime = GetTickCount64();

			// [Fix: 지연 BSOD 허용] 50ms 루프 기준 임계값. 지연성 0x1E BSOD가 완성될 때까지 워커를 성급히 사살하지 않는다.
			constexpr DWORD LOOP_SLEEP_MS = 50;
			constexpr int   MASS_HANG_STALL_TICKS = 40;      // 2초 연속 CPU 정지 -> 'stall'로 집계(순간 스케줄 공백 오탐 차단)
			constexpr int   PROLONGED_DEADLOCK_DIAG_TICKS = 24000; // [Fix] 사살 아님: ~20분 무진척 시 '진단 로그 1회' 임계(워커는 방치)
			// [Fix: P2] 고립(Isolated) Hang 재기동 임계. mass-hang 감지(2초)보다 훨씬 길고, 장기 방치 진단(~20분)보다
			//   짧게 두어 '지연 BSOD 대기' 의도를 해치지 않으면서 고립 데드락으로 인한 처리량 저하를 회복한다.
			constexpr int   ISOLATED_HANG_KILL_TICKS = 3600; // 50ms * 3600 = 180초(3분) 고립 정지 시 kill+respawn

			// [Fix: Mass Hang 오판 방지] 동시 정지 워커가 과반이면 '드라이버 전멸(Global DoS/BSOD 진행)'로 간주하여 무한 대기.
			const size_t massHangHalf = (workers_.size() + 1) / 2;
			const size_t massHangThreshold = (massHangHalf < 2) ? 2 : massHangHalf;
			// [Fix: P2] 워커가 1개뿐이면 '동시 다발(mass)' 개념 자체가 성립하지 않는다(massHangThreshold 최소 2 > 최대 정지 수 1).
			//   이 경우 mass-hang 판정을 비활성화하고, 단일 워커 정지는 아래 고립(Isolated) Hang 경로가 kill+respawn으로 처리한다.
			const bool massHangPossible = (workers_.size() >= 2);
			bool massHangLatched = false; // 전역 정지 안내 로그 1회 래치(50ms 스팸 방지)

			while (true) {
				if (GetTickCount64() - lastWindowTime > 1000) {
					globalRapidDeathCount = 0;
					lastWindowTime = GetTickCount64();
				}

				// [Fix: Mass Hang 판정용] 이번 스캔의 정지 워커 수와 유예 만료된 고립 데드락 후보를 먼저 수집한다.
				size_t stalledCount = 0;
				// [Fix: P2] 고립(Isolated) 장기 정지 후보 인덱스. 실제 kill은 'Mass Hang이 아님'을 확인한 뒤 루프 종료 후 결정한다.
				std::vector<size_t> isolatedHangCandidates;

				for (size_t i = 0; i < workers_.size(); ++i) {

					auto& worker = workers_[i];

					if (worker.Wait(0)) {
						DWORD exitCode = 0;
						GetExitCodeProcess(worker.GetProcessHandle(), &exitCode);

						// [Fix: BSOD 오판 방지] 동시 급사는 인프라 오류가 아니라 드라이버 전멸(BSOD 진행) 신호일 수 있으므로
						//   마스터를 자폭시키지 않는다. 자폭(Abort) 트리거는 폐기하고 진단용 경고만 1회 남긴 뒤 재기동을 계속한다.
						if (exitCode != 0) {
							globalRapidDeathCount++;
							if (globalRapidDeathCount == 10) { // 1초 창 내 10회: 종료 대신 경고만
								std::wcout << L"\n[WARN] High worker death rate in <1s window "
									<< L"(possible driver-wide DoS / BSOD in progress). Master keeps waiting & respawning.\n";
							}
						}

						// [TCP 전환] 유죄 시드 회수/덤프는 호스트가 담당하므로 여기선 즉시 재기동만 수행
						std::wstring cmdLine = BuildWorkerCmdLine(exePath, static_cast<DWORD>(i), sessionDir);
						WinKernel::Process::WorkerProcess newWorker;

						if (newWorker.Launch(static_cast<DWORD>(i), cmdLine.c_str())) {
							worker = std::move(newWorker);
							hangCounters[i] = 0;
							lastCpuTimes[i] = 0;	// [추가] 재생성된 워커의 CPU 시간 베이스라인 초기화(오탐 Hang 방지)
						}
					}
					// [Design: 오탐 Hang 방지] CPU 진척이 있으면(퍼징 중) 살려두고, 진척 0 상태만 집계한다(사살 판정은 루프 종료 후).
					else {
						if (worker.IsRunning()) {
							// 워커 프로세스의 커널/유저 CPU 사용 시간 조회
							FILETIME createTime, exitTime, kernelTime, userTime;
							if (GetProcessTimes(worker.GetProcessHandle(), &createTime, &exitTime, &kernelTime, &userTime)) { //worker.GetProcessHandle()은 WorkerProcess 클래스에 있는 hProcess_ 핸들을 반환하는 게터 함수입니다.
								ULARGE_INTEGER k, u;
								k.LowPart = kernelTime.dwLowDateTime; k.HighPart = kernelTime.dwHighDateTime;
								u.LowPart = userTime.dwLowDateTime;   u.HighPart = userTime.dwHighDateTime;
								ULONGLONG totalCpu = k.QuadPart + u.QuadPart;

								if (totalCpu > lastCpuTimes[i]) {
									// CPU를 쓰면서 700만 회 퍼징을 열심히 돌리는 중 -> 정상 (카운터 초기화)
									hangCounters[i] = 0;
									lastCpuTimes[i] = totalCpu;
								} else {
									// CPU 시간이 멈춰있음 (드라이버 락/무한 대기로 멈춘 상태) -> 카운터 증가
									hangCounters[i]++;
									// [Fix: 즉시 사살 폐기] 여기서 곧바로 죽이지 않고 정지 상태만 집계한다. 실제 사살 여부는
									//   Mass Hang(전역 정지) 여부를 확인한 뒤 루프 종료 후 결정한다(지연 BSOD 완성 대기).
									if (hangCounters[i] >= MASS_HANG_STALL_TICKS) stalledCount++;
									// [Fix: P2] 고립 장기 정지 후보 수집. 실제 kill 여부는 Mass Hang 아님을 확인한 뒤 루프 종료 후 결정한다.
									if (hangCounters[i] >= ISOLATED_HANG_KILL_TICKS) isolatedHangCandidates.push_back(i);
									// [Fix: P2] 이 진단 로그(~20분)는 '고립 kill(180초)'이 Mass Hang 게이트로 계속 유보된 경우에만 도달한다.
									//   즉 여기까지 왔다는 것은 지속적 Mass Hang 상태이므로, 커널이 스스로 뻗을 때까지 방치가 맞다. '=='로 1회만 로그(스팸 차단).
									if (hangCounters[i] == PROLONGED_DEADLOCK_DIAG_TICKS) {
										std::wcout << std::format(
											L"[DIAG] Worker {} unresponsive ~{}s post-IOCTL. LEAVING it alive (NO terminate) so a delayed BSOD (0x1E) can complete.\n",
											i, (static_cast<long long>(PROLONGED_DEADLOCK_DIAG_TICKS) * LOOP_SLEEP_MS) / 1000);
									}
								}
							}
						}
					}
				}

				// [Fix: Mass Hang 무한 대기] 과반 워커가 동시에 정지했다면 개별 인프라 문제가 아니라 드라이버 전멸(BSOD 진행)이다.
				//   이 경우 어떤 워커도 사살하지 않고 커널 예외(BSOD)가 완성될 때까지 무한 대기한다(고립 데드락 사살도 유보).
				if (massHangPossible && stalledCount >= massHangThreshold) {
					if (!massHangLatched) {
						std::wcout << std::format(
							L"\n[GLOBAL STALL] {}/{} workers frozen simultaneously -> driver-wide DoS / imminent BSOD.\n"
							L"[*] Master will NOT terminate ANY worker; waiting indefinitely for the kernel exception (0x1E) to complete...\n",
							stalledCount, workers_.size());
						massHangLatched = true;
					}
				}
				else {
					massHangLatched = false;
					// [Fix: P2] Mass Hang이 아닌 경우에 한해, 고립(Isolated) 장기 정지 워커를 kill+respawn 한다.
					//   '다른 워커는 CPU 진척 중(stalledCount < 과반)'이므로 커널은 살아있고, 이 정지는 드라이버 전멸(BSOD 진행)이
					//   아니라 순수 SW 데드락일 가능성이 높다 -> 처리량 회복을 위해 재기동. (Mass Hang 상태에서는 절대 죽이지 않음)
					for (size_t idx : isolatedHangCandidates) {
						auto& worker = workers_[idx];
						if (!worker.IsRunning()) continue; // 이미 종료됐다면 다음 스캔의 exited-respawn 경로가 처리
						std::wcout << std::format(
							L"[ISOLATED HANG] Worker {} stalled ~{}s while other workers progress -> kill+respawn "
							L"(likely SW deadlock, not driver-wide BSOD).\n",
							idx, (static_cast<long long>(ISOLATED_HANG_KILL_TICKS) * LOOP_SLEEP_MS) / 1000);
						worker.Kill(0); // TerminateProcess; 뒤이은 이동대입의 Close()가 killed 핸들을 닫는다.
						std::wstring cmdLine = BuildWorkerCmdLine(exePath, static_cast<DWORD>(idx), sessionDir);
						WinKernel::Process::WorkerProcess newWorker;
						if (newWorker.Launch(static_cast<DWORD>(idx), cmdLine.c_str())) {
							worker = std::move(newWorker);
							hangCounters[idx] = 0;
							lastCpuTimes[idx] = 0; // 재기동 워커 CPU 베이스라인 초기화(오탐 Hang 방지)
						}
					}
				}

				Sleep(LOOP_SLEEP_MS);
			}
		}
	};
}