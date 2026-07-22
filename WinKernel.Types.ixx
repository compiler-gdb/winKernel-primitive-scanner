//프로젝트 전체에서 사용되는 구조체, 열거형, 공통 상수 정의 담당.
//패킷 구조체나 IPC 메시지 포맷 변경 필요 시 Types에 문제가 존재한다고 판단할 수 있습니다.

module;
#include <windows.h>

export module WinKernel.Types;

export namespace WinKernel {
	namespace Types {
		enum class WorkerState {
			Idle,
			Running,
			Crashed,
			Finished
		};

		struct FuzzPacket {
			DWORD ioctlCode;
			ULONG_PTR targetAddress; // ULONG_PTR: 포인터 크기와 완전히 동일한 크기를 가지는 정수 타입. void* 같은 경우는 주소를 가르키지만 더하기, 빼기, 비트 연산 등이 불가합니다.
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

	namespace Constants {
		constexpr DWORD MAX_WORKERS = 32;
		constexpr DWORD DEFAULT_BUFFER_SIZE = 4096;
		constexpr DWORD IPC_TIMEOUT_MS = 5000;
		constexpr wchar_t LOG_FILE_PATH[] = L"crash_blackbox.log";
		// wchar_t: 한글, 한자, 이모지 등 전 세계 유니코드(UFT-16)문자를 깨짐없이 다루기 위한 2byte 크기의 타입.
		// "crash_blakckbox.log" 앞의 L 접두사는 컴파일러에게 wchar_t 유니코드 배열로 저장하라고 지시하는 접두사입니다. wchar_t 유니코드 배열로 저장한다는 의미입니다.
		// 윈도우 NT 커널 및 Win32 API는 기본적으로 UTF-16유니코드 기반으로 만들어져 있습니다.
		
		// CreateFileW: 파일, 디바이스 또는 파이프를 생성하거나 열고 해당 핸들을 반환하는 함수입니다.
		// CreateFileW에서 lpFileName은 LPCWSTR 타입입니다. Log Pointer to Constant Wide String의 약자이며 const wchar_t*를 의미합니다.
		// char 타입을 사용하고 접두사 L을 제외하면 실행이 되지 않습니다. CreateFileA는 실행은 되지만 출력이 깨질 수 있기 때문에 경로 깨짐이나 런타임 버그가 일어날 수 있습니다.
		// CreateFileW의 구조는 아래와 같습니다. 
		/*
		HANDLE WINAPI CreateFileW(
		  LPCWSTR               lpFileName,           // 파일 경로
		  DWORD                 dwDesiredAccess,      // 접근 권한 (읽기: GENERIC_READ, 쓰기: GENERIC_WRITE)
		  DWORD                 dwShareMode,          // 공유 모드 (0: 독점, FILE_SHARE_READ 등)
		  LPSECURITY_ATTRIBUTES lpSecurityAttributes, // 보안 속성 (보통 NULL)
		  DWORD                 dwCreationDisposition,// 생성 방식 (새로 생성: CREATE_ALWAYS 등)
		  DWORD                 dwFlagsAndAttributes, // 파일 속성 및 플래그 (FILE_ATTRIBUTE_NORMAL 등)
		  HANDLE                hTemplateFile         // 템플릿 파일 핸들 (보통 NULL)
		);
		*/
	}
}