//프로젝트 전체에서 사용되는 구조체, 열거형, 공통 상수 및 RAII 유틸리티 정의 담당.
//패킷 구조체나 IPC 메시지 포맷 변경 필요 시 Types에 문제가 존재한다고 판단할 수 있습니다.

module;
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <stdint.h>

export module WinKernel.Types;

export namespace WinKernel {
	namespace Types {
		enum class WorkerState {
			Idle,
			Running,
			Crashed,
			Finished
		};

		// [Fix: Host의 크래시 판정 결과 분류용] 워커 종료 결과를 오탐/실크래시/행으로 구분
		enum class CrashClass {
			Benign,   // 정상 종료 또는 양성 거부 (덤프 대상 아님)
			Crash,    // 0xC0000005 등 비정상 예외 코드로 강제 종료
			Hang      // 비동기 I/O 타임아웃(Deadlock)으로 확정
		};

		struct FuzzPacket {
			DWORD ioctlCode;
			ULONG_PTR targetAddress; // ULONG_PTR: 포인터 크기와 완전히 동일한 크기를 가지는 정수 타입.
			DWORD bufferSize;
			BYTE payload[256];
		};

		struct SharedWorkerStatus {
			DWORD workerID;
			WorkerState state;
			DWORD lastIoctl;
			ULONG_PTR lastAddress;
		};
	}

	// [Fix: Win32 핸들 누수 원천 차단] 센티널 정책 기반 RAII 핸들/뷰 래퍼 모음
	namespace Sys {
		// CreateFileW 실패 센티널: INVALID_HANDLE_VALUE
		struct FileHandlePolicy { static HANDLE Invalid() noexcept { return INVALID_HANDLE_VALUE; } };
		// CreateEvent/CreateFileMapping 실패 센티널: nullptr
		struct NullHandlePolicy { static HANDLE Invalid() noexcept { return nullptr; } };

		// [Fix: nullptr vs INVALID_HANDLE_VALUE 센티널 일관성] 정책으로 무효값을 강제 통일
		template <typename Policy>
		class UniqueHandle {
			HANDLE h_{ Policy::Invalid() };
		public:
			UniqueHandle() noexcept = default;
			explicit UniqueHandle(HANDLE h) noexcept : h_(h) {}
			~UniqueHandle() { Reset(); }

			UniqueHandle(const UniqueHandle&) = delete;
			UniqueHandle& operator=(const UniqueHandle&) = delete;

			UniqueHandle(UniqueHandle&& other) noexcept : h_(other.h_) {
				other.h_ = Policy::Invalid();
			}
			UniqueHandle& operator=(UniqueHandle&& other) noexcept {
				if (this != &other) {
					Reset();
					h_ = other.h_;
					other.h_ = Policy::Invalid();
				}
				return *this;
			}

			HANDLE Get() const noexcept { return h_; }
			bool Valid() const noexcept { return h_ != Policy::Invalid(); }
			explicit operator bool() const noexcept { return Valid(); }

			HANDLE Release() noexcept {
				HANDLE t = h_;
				h_ = Policy::Invalid();
				return t;
			}
			void Reset(HANDLE h = Policy::Invalid()) noexcept {
				if (h_ != Policy::Invalid()) {
					CloseHandle(h_);
				}
				h_ = h;
			}
		};

		using FileHandle = UniqueHandle<FileHandlePolicy>;    // CreateFileW 결과 전용
		using KernelHandle = UniqueHandle<NullHandlePolicy>;  // CreateEvent/CreateFileMapping 결과 전용

		// [Fix: MapViewOfFile 매핑 누수 차단] 포인터 뷰 전용 RAII (UnmapViewOfFile 딜리터)
		class MappedView {
			void* p_{ nullptr };
		public:
			MappedView() noexcept = default;
			explicit MappedView(void* p) noexcept : p_(p) {}
			~MappedView() { Reset(); }

			MappedView(const MappedView&) = delete;
			MappedView& operator=(const MappedView&) = delete;

			MappedView(MappedView&& other) noexcept : p_(other.p_) { other.p_ = nullptr; }
			MappedView& operator=(MappedView&& other) noexcept {
				if (this != &other) {
					Reset();
					p_ = other.p_;
					other.p_ = nullptr;
				}
				return *this;
			}

			void* Get() const noexcept { return p_; }
			bool Valid() const noexcept { return p_ != nullptr; }
			void Reset(void* p = nullptr) noexcept {
				if (p_) UnmapViewOfFile(p_);
				p_ = p;
			}
		};
	}

	namespace Constants {
		constexpr DWORD MAX_WORKERS = 32;
		constexpr DWORD DEFAULT_BUFFER_SIZE = 4096;

		constexpr wchar_t TARGET_DRIVER_NAME[] = L"HackSysExtremeVulnerableDriver";
		constexpr DWORD TARGET_IOCTL_CODE = 0x222003;
		constexpr uint64_t MAX_WORKER_ITERATIONS = 7'000'000;

		// [Fix: 가변 크기 이스케일레이션 제거] 4096(PAGE_SIZE) 고정 크기 입력에서 드라이버 취약점이 직격 재현되는 것을 확인 -> 모든 페이로드를 DEFAULT_BUFFER_SIZE로 고정.

		// [Fix: '다음 IOCTL로 진행' 요구 대응] 순차 검증할 타깃 IOCTL 목록 (확장 가능)
		constexpr DWORD TARGET_IOCTL_CODES[] = { 0x222003 };
		constexpr size_t TARGET_IOCTL_COUNT = sizeof(TARGET_IOCTL_CODES) / sizeof(TARGET_IOCTL_CODES[0]);

		// IOCTL당 4096바이트 고정 페이로드로 수행할 변조 반복 횟수
		constexpr uint32_t ITERATIONS_PER_PROFILE = 256;

		// [TCP IPC 계약] 워커(TCP Client) -> 호스트(monitoring.py TCP Server) 온-와이어 리포트 규약.
		// 파일/HGFS 기반 상태 저장을 전면 폐기하고, 유죄 후보를 소켓으로 직접 스트리밍한다.
		// Python은 struct.Struct("<8IQ2I256s")로 총 304바이트 고정 레코드를 1:1 언패킹한다.
		constexpr uint32_t REPORT_MAGIC = 0x5043544Bu; // 리틀엔디언 'K','T','C','P' -> struct.pack("<I") == b"KTCP"
		constexpr uint32_t REPORT_VERSION = 1;
		// 온-와이어 페이로드 스냅샷 상한(유죄 후보 앞부분). FuzzReportPacket.payload 크기와 반드시 일치.
		constexpr uint32_t REPORT_PAYLOAD_MAX = 256;
		// 호스트 TCP 리스너 기본 포트(monitoring.py LISTEN_PORT와 일치, --report-port로 상시 오버라이드).
		constexpr uint16_t REPORT_PORT = 51337;

		// [TCP 전환] 파일 기반 체크포인트/블랙리스트/공유폴더 경로 상수는 전면 폐기했다.
		// 유죄 시드 판정은 이제 소켓 절단(BSOD)과 Crashed 리포트로 호스트가 직접 수행한다.
	}
}
