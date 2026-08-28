/*
[TCP Socket IPC — 파일/HGFS 기반 상태 저장 전면 폐기 후 재설계]

 [설계 배경]
  - 기존: 워커가 SHM/.livecp/.stage/blacklist를 게스트 로컬 디스크에 기록 -> BSOD 후 Host가 vmrun으로 pull.
    HGFS 쓰기 차단/flush 비내구/revert 소실/pull 지연 등 파일 파이프라인의 취약점이 컸다.
  - 신규: 워커가 DeviceIoControl '직전'마다 유죄 후보(시드/IOCTL)를 호스트 TCP 서버로 직접 send.
    BSOD로 소켓이 끊기면 '마지막으로 흘러든 InIoctl 패킷'이 곧 유죄 시드다(디스크 경유 없음).

 [Guest (워커) = TCP Client]
  1. 초기화 시 TcpReporter::Connect()로 호스트 리스너에 접속(TCP_NODELAY로 Nagle 지연 제거 -> 마지막 패킷 즉시 송출).
  2. DeviceIoControl 진입 직전 Report(InIoctl, ...)로 현재 시드/IOCTL/크기/페이로드 스냅샷을 전송.
  3. 유저모드 SEH 흡수 예외는 Report(Crashed, exceptionCode)로 통지(소켓 유지, 퍼징 지속).
  4. 매트릭스 완주는 Report(Completed)로 통지 후 정상 재활용.

 [온-와이어 계약]
  - 고정 304바이트 POD 레코드(#pragma pack(1))를 그대로 스트리밍. Python은 struct.Struct("<8IQ2I256s")로 1:1 언패킹.
  - class가 아닌 표준 레이아웃 struct를 쓰는 이유: 가상함수/상속이 주입하는 vptr은 프로세스마다 주소가 달라
    바이트 스트림 계약을 깨뜨린다. 따라서 순수 POD로 유지한다.
*/

module;
#define WIN32_LEAN_AND_MEAN // [Fix: 헤더 격리 규칙 준수] Win32 심볼 최소화
#define NOMINMAX            // [Fix: min/max 매크로 오염 차단]
#include <winsock2.h>       // [Fix: winsock2는 windows.h보다 먼저] ws2def/ws2tcpip 충돌 방지
#include <ws2tcpip.h>       // getaddrinfo/inet_pton
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <string>

#pragma comment(lib, "Ws2_32.lib") // [Fix: WS2_32 링크] 모듈 자체가 소켓 의존성을 자가 선언(빌드 설정 무변경)

export module WinKernel.IPC;

import WinKernel.Types; // Constants(REPORT_* 계약) 재사용

export namespace WinKernel::IPC {

	// [Design: Host의 유죄/진척 판정 근거] 워커의 IOCTL 생애주기 단계. Python PHASE_NAMES와 값이 1:1 일치해야 한다.
	enum class WorkerPhase : uint32_t {
		Init = 0,   // 접속 직후
		PreIoctl,   // (예약) 준비 완료
		InIoctl,    // 커널 진입 직전 (여기서 소켓이 끊기면 BSOD 유죄 유력 지점)
		PostIoctl,  // (예약) 정상 반환
		Completed,  // 워커 매트릭스 완주 (유죄 아님)
		Crashed     // 유저모드 SEH 흡수 예외 (exceptionCode 동반, 소켓 유지)
	};

	// [Design: 온-와이어 고정 레코드] Host(Python)와 바이트 레이아웃을 공유하는 고정 크기 POD.
	// pack(1)로 패딩을 제거해 struct.unpack("<8IQ2I256s")와 1:1 대응(총 304바이트).
#pragma pack(push, 1)
	struct FuzzReportPacket {
		uint32_t magic;         // REPORT_MAGIC ('KTCP') — 유효/찢김 판별
		uint32_t version;       // REPORT_VERSION
		uint32_t workerId;
		uint32_t phase;         // WorkerPhase
		uint32_t ioctlCode;
		uint32_t seed;
		uint32_t declaredSize;  // 극단값 포함 선언 크기
		uint32_t actualSize;    // 실제 전송 버퍼 크기
		uint64_t iteration;
		uint32_t exceptionCode; // 유저모드 흡수 예외 코드(없으면 0)
		uint32_t payloadLen;    // <= REPORT_PAYLOAD_MAX
		uint8_t  payload[WinKernel::Constants::REPORT_PAYLOAD_MAX]; // 유죄 페이로드 앞부분 스냅샷
	};
#pragma pack(pop)

	// [Design: 워커 -> 호스트 단방향 리포터(RAII)] WSAStartup/socket 자원을 단일 소유하고 소멸 시 정리.
	// 실패는 모두 조용히 흡수한다(퍼징은 리포팅 없이도 지속) — 자가 회복 원칙 유지.
	class TcpReporter {
		SOCKET sock_{ INVALID_SOCKET };
		bool wsaReady_{ false };
		DWORD workerId_{ 0 };
		int lastError_{ 0 }; // [Diag: 접속 실패 원인 국소화] WSAGetLastError 보존

		// [Fix: P4] send() 송신 타임아웃(ms). 304B 레코드+TCP_NODELAY 환경에서 정상 송신은 즉시 끝나므로,
		//   이 값은 '호스트가 소켓을 드레인하지 못하는 wedged 상태(응답 지연/단절)'의 상한선으로만 작동한다.
		static constexpr DWORD kSendTimeoutMs = 5000;

		// [Fix: wide 호스트명을 narrow로] getaddrinfo는 ANSI 문자열을 받는다. ASCII IP/호스트명만 사용.
		static std::string ToNarrow(const std::wstring& w) {
			if (w.empty()) return std::string();
			int len = WideCharToMultiByte(CP_ACP, 0, w.c_str(), static_cast<int>(w.size()),
				nullptr, 0, nullptr, nullptr);
			std::string s(static_cast<size_t>(len), '\0');
			WideCharToMultiByte(CP_ACP, 0, w.c_str(), static_cast<int>(w.size()),
				s.data(), len, nullptr, nullptr);
			return s;
		}

	public:
		TcpReporter() = default;
		~TcpReporter() { Close(); }

		// 복사 금지 / 이동 허용 (소켓 단일 소유)
		TcpReporter(const TcpReporter&) = delete;
		TcpReporter& operator=(const TcpReporter&) = delete;
		TcpReporter(TcpReporter&& o) noexcept
			: sock_(o.sock_), wsaReady_(o.wsaReady_), workerId_(o.workerId_), lastError_(o.lastError_) {
			o.sock_ = INVALID_SOCKET; o.wsaReady_ = false;
		}
		TcpReporter& operator=(TcpReporter&& o) noexcept {
			if (this != &o) {
				Close();
				sock_ = o.sock_; wsaReady_ = o.wsaReady_; workerId_ = o.workerId_; lastError_ = o.lastError_;
				o.sock_ = INVALID_SOCKET; o.wsaReady_ = false;
			}
			return *this;
		}

		// [Design: 호스트 리스너 접속] 서버가 아직 안 떴을 수 있으므로 짧게 재시도. 실패해도 예외 없이 false 반환.
		bool Connect(const std::wstring& host, uint16_t port, DWORD workerId, int retries = 20) {
			workerId_ = workerId;

			WSADATA wsa{};
			if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { lastError_ = WSAGetLastError(); return false; }
			wsaReady_ = true;

			const std::string hostA = ToNarrow(host);
			const std::string portA = std::to_string(port);

			addrinfo hints{};
			hints.ai_family = AF_INET;       // IPv4 고정(호스트-게스트 vmnet)
			hints.ai_socktype = SOCK_STREAM; // TCP
			hints.ai_protocol = IPPROTO_TCP;

			for (int attempt = 0; attempt < retries; ++attempt) {
				addrinfo* res = nullptr;
				if (getaddrinfo(hostA.c_str(), portA.c_str(), &hints, &res) == 0 && res) {
					SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
					if (s != INVALID_SOCKET) {
						if (connect(s, res->ai_addr, static_cast<int>(res->ai_addrlen)) == 0) {
							// [Fix: Nagle 지연 제거] BSOD 직전 마지막 InIoctl 패킷이 커널 버퍼에 갇히지 않고 즉시 송출되게 한다.
							BOOL nodelay = TRUE;
							setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
								reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
							// [Fix: P4] send() 무한 블로킹 방지: 호스트 응답 지연/네트워크 단절 시에도 워커가 무한정 멈추지 않도록
							//   송신 타임아웃(SO_SNDTIMEO)을 설정한다. 타임아웃 시 send()가 SOCKET_ERROR(WSAETIMEDOUT)로 반환되고,
							//   Report()의 기존 실패 경로가 소켓만 무효화한 뒤 퍼징은 계속한다("리포트 실패는 치명적이지 않게").
							//   (Windows의 SO_SNDTIMEO는 POSIX의 timeval이 아니라 밀리초 DWORD를 받는다.)
							DWORD sndTimeoutMs = kSendTimeoutMs;
							setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
								reinterpret_cast<const char*>(&sndTimeoutMs), sizeof(sndTimeoutMs));
							sock_ = s;
							freeaddrinfo(res);
							return true;
						}
						closesocket(s);
					}
					freeaddrinfo(res);
				}
				lastError_ = WSAGetLastError();
				Sleep(500); // 서버 리스너 기동 대기(호스트가 퍼저 실행 직전 listen)
			}
			return false;
		}

		bool Valid() const noexcept { return sock_ != INVALID_SOCKET; }
		int LastError() const noexcept { return lastError_; } // [Diag: 접속 실패 코드]

		// [Design: IOCTL 직전 유죄 후보 송신] 고정 레코드를 전량 전송(부분 전송 루프). 실패 시 소켓을 무효화(퍼징 지속).
		// SHM/디스크 경유 없이 호스트 RAM에 곧바로 유죄 시드가 남으므로 revert 전 별도 수거가 필요 없다.
		void Report(WorkerPhase phase, DWORD ioctlCode, uint32_t seed,
			uint32_t declaredSize, uint32_t actualSize, uint64_t iteration,
			DWORD exceptionCode, const void* data, uint32_t dataLen) {
			if (sock_ == INVALID_SOCKET) return;

			FuzzReportPacket pkt{};
			pkt.magic = WinKernel::Constants::REPORT_MAGIC;
			pkt.version = WinKernel::Constants::REPORT_VERSION;
			pkt.workerId = workerId_;
			pkt.phase = static_cast<uint32_t>(phase);
			pkt.ioctlCode = ioctlCode;
			pkt.seed = seed;
			pkt.declaredSize = declaredSize;
			pkt.actualSize = actualSize;
			pkt.iteration = iteration;
			pkt.exceptionCode = exceptionCode;

			uint32_t copyLen = dataLen;
			if (copyLen > WinKernel::Constants::REPORT_PAYLOAD_MAX) {
				copyLen = WinKernel::Constants::REPORT_PAYLOAD_MAX;
			}
			if (data && copyLen) std::memcpy(pkt.payload, data, copyLen);
			pkt.payloadLen = copyLen;

			const char* buf = reinterpret_cast<const char*>(&pkt);
			int total = static_cast<int>(sizeof(pkt));
			int sent = 0;
			while (sent < total) {
				int n = send(sock_, buf + sent, total - sent, 0);
				if (n == SOCKET_ERROR || n == 0) {
					// [Fix: 송신 실패는 치명적이지 않게] 소켓을 무효화만 하고 반환 -> 워커는 리포팅 없이 계속 퍼징
					lastError_ = WSAGetLastError();
					closesocket(sock_);
					sock_ = INVALID_SOCKET;
					return;
				}
				sent += n;
			}
		}

		// [Design: 정상 재활용 마감] 완주/종료 시 소켓을 정상 닫아 Host가 유죄로 오탐하지 않게 한다.
		void Close() {
			if (sock_ != INVALID_SOCKET) {
				shutdown(sock_, SD_SEND); // FIN으로 정상 종료 통지(BSOD의 비정상 절단과 구분)
				closesocket(sock_);
				sock_ = INVALID_SOCKET;
			}
			if (wsaReady_) {
				WSACleanup();
				wsaReady_ = false;
			}
		}
	};
}
