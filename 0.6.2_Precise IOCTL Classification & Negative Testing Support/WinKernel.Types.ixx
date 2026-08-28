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

		// [가변 크기 퍼징] 페이로드 크기를 매 반복 이 범위에서 무작위(시드 결정론)로 선택한다.
		// 기존처럼 크기를 4096으로 고정하면 HEVD 스택 버퍼(~2048B)를 무조건 넘겨 "모든 반복이 크래시"가 되어
		// 시드/변조가 크래시 발생 여부와 무관해진다. 크기를 [MIN, MAX]로 흔들어 임계값 미만(음성)과
		// 초과(양성)를 모두 관측할 수 있게 하여 실제 탐색이 성립하도록 한다.
		constexpr uint32_t MIN_PAYLOAD_SIZE = 1;
		constexpr uint32_t MAX_PAYLOAD_SIZE = 8192;

		constexpr wchar_t TARGET_DRIVER_NAME[] = L"HackSysExtremeVulnerableDriver";
		constexpr DWORD TARGET_IOCTL_CODE = 0x222003;
		constexpr uint64_t MAX_WORKER_ITERATIONS = 7'000'000;

		// [Fix: 가변 크기 이스케일레이션 제거] 4096(PAGE_SIZE) 고정 크기 입력에서 드라이버 취약점이 직격 재현되는 것을 확인 -> 모든 페이로드를 DEFAULT_BUFFER_SIZE로 고정.

		// [Fix: '다음 IOCTL로 진행' 요구 대응] 순차 검증할 타깃 IOCTL 목록 (확장 가능)
		constexpr DWORD TARGET_IOCTL_CODES[] = { 0x222003 };
		constexpr size_t TARGET_IOCTL_COUNT = sizeof(TARGET_IOCTL_CODES) / sizeof(TARGET_IOCTL_CODES[0]);

		// [실무형 구조적 랜덤 IOCTL] 시드 코퍼스 + CTL_CODE 구조 변이 기반의 '재현 가능한' 랜덤 모드 프로파일.
		//   완전 32비트 균일 랜덤은 device type 불일치로 거의 전부 default 분기(무크래시)라 비효율적이다.
		//   대신 알려진 유효 코드를 재사용(exploitation)하고, CTL_CODE 레이아웃을 지켜 인접 공간만 탐색(exploration)한다.
		//   이 모드는 opt-in(--ioctl-random)이며, 기본 리스트 모드(TARGET_IOCTLS)는 그대로 두어 검증 재현성을 해치지 않는다.
		constexpr uint32_t HEVD_IOCTL_CORPUS[] = {
			0x222007, // BUFFER_OVERFLOW_STACK_GS
			0x22200B, // ARBITRARY_OVERWRITE
			0x22200F, // POOL_OVERFLOW
			0x222013, // ALLOCATE_UAF_OBJECT
			0x222017, // USE_UAF_OBJECT
			0x22201B, // FREE_UAF_OBJECT
			0x222003, // BUFFER_OVERFLOW_STACK (맨 뒤로 이동)
		};
		constexpr size_t HEVD_IOCTL_CORPUS_COUNT = sizeof(HEVD_IOCTL_CORPUS) / sizeof(HEVD_IOCTL_CORPUS[0]);
		constexpr uint16_t TARGET_DEVICE_TYPE = 0x22;    // HEVD 의 FILE_DEVICE_UNKNOWN 대역(CTL_CODE 상위 16비트)
		constexpr uint32_t IOCTL_FUNC_MIN = 0x800;       // HEVD Function 시작 번호
		constexpr uint32_t IOCTL_FUNC_MAX = 0x8FF;       // 인접 미정의 Function 까지 탐색 상한
		constexpr uint32_t IOCTL_EXPLOIT_PCT = 70;       // 이 %만큼 코퍼스(알려진 유효 코드) 재사용, 나머지는 구조적 탐색
		constexpr uint32_t IOCTL_METHOD_RANDOM_PCT = 10; // 이 %만큼 method 무작위(그 외에는 METHOD_NEITHER=3 유지)

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
