//자식 프로세스의 생성, 대기, 강제 종료 생명주기 관리.
//자식 프로세스가 안떠서 멀티프로세싱이 안되면 해당 파일에 문제가 존재한다고 판달할 수 있습니다.

module;
#include <Windows.h>
#include <string>	// [추가] Launch()의 std::wstring 가변 버퍼용

export module WinKernel.Process;

import WinKernel.Types;

export namespace WinKernel::Process {

	class WorkerProcess {

	//변수 이름 뒤에 언더바가 왜 이렇게 많은가?
	//코딩 스타일 중 하나 정도입니다.
	//클래스 안에서 사용하는 멤버 변수라는 점을 구분하기 위함입니다.
	private:
		DWORD id_{ 0 };
		HANDLE hProcess_{ NULL };
		HANDLE hThread_{ NULL };
		DWORD processId_{ 0 };
		WinKernel::Types::WorkerState state_{ WinKernel::Types::WorkerState::Idle };

	public:
		WorkerProcess() = default; //생성자를 지정합니다. default로 할 경우 이전 프로그램이 쓰고 남긴 자리를 0으로 리셋해줍니다.
		//우리가 밑에서 만든 WorkerProcess 이동자 등을 만들면 C++에서는 자원 관리가 특수한 경우라고 판단, 생성자가 사라집니다. 결과적으로 인자 없는 객체 생성, 배열 생성 등의 작업에서 컴파일 에러가 발생합니다.

		~WorkerProcess() {
			Close();
		}

		//복사를 방지합니다.
		WorkerProcess(const WorkerProcess&) = delete;
		WorkerProcess& operator=(const WorkerProcess&) = delete;

		// 이동을 허용합니다. vector 등에 담을 수 있도록 설정합니다.
		/*
			(WorkerProcess&& other)에서 &&는 무엇인가?
			이제 곧 사라질 임시 객체를 의미.
			기존의 객체를 복사하지 않고 이동시켜서 사용하겠다는 의미입니다.

			noexcept는 무엇인가?
			이 함수는 실행 중에 절대로 예외를 발생시키지 않는다고 컴파일러에서 지시합니다.
			이 함수의 이동 작업을 안전하고 빠르게 처리하도록 돕습니다.

			왜 변수 옆에 괄호 안에도 언더바가 계속 있는가?
			멤버 초기화 리스트 문법입니다.
			id_(other.id_)는 내 id_변수를 other의 id_ 값으로 초기화하겠다는 뜻입니다.

			왜 hProcess와 hThread는 NULL로 초기화 하는가?
			상대방 핸들을 뺏어온 것이기 때분에 상대방이 가지고 있던 연결고리를 끊어주기 위함입니다. 이를 초기화하지 않으면 나중에 상대방 객체 소멸 시 내가 가져온 자원까지 삭제되어 에러가 발생합니다.

			state_만 원본을 Idle로 바꾸는 이유는?
			hProcess_나 Thread_는 윈도우 시스템이 관리하는 포인터/핸들 자원이지만 state_는 포인터가 아니라 상태를 나타내는 데이터입니다.(열거형/Enum) 그러므로 아무것도 안한다는 Idle로 초기화합니다.
			*/
		// WorkerProcess라는 클래스 타입의 객체를 전달받는 other 변수.
		WorkerProcess(WorkerProcess&& other) noexcept	// noexcept: 사용자는 이 함수는 무조건 에러가 터지지 않을거라하여 컴파일러가 일단 실행하고, 예외 발생 시 즉시 강제 종료.
			: id_(other.id_), hProcess_(other.hProcess_), hThread_(other.hThread_),
			processId_(other.processId_), state_(other.state_) {
			other.hProcess_ = NULL;
			other.hThread_ = NULL;
			other.state_ = WinKernel::Types::WorkerState::Idle;			// Process.ixx 내의 함수들에 따른 state_ 변화에 따라 맨 아래의 GetState의 반환 값이 달라집니다.
		}

		//자식 워커 프로세스를 실행합니다.
		//STARTUPINFOW에서 sizeof(si)를 꼭 붙혀야 하나?
		//윈도우가 프로그램을 띄울 때 참고하는 설정 데이터 묶음인 STARTUPINFOW는 OS 버전별로 기능이 추가되며 크기가 다릅니다. 어디까지 읽을지 판단할 수 있게 되며 뒤에 쓰래기 값을 무시하게 됩니다.
		bool Launch(DWORD id, const wchar_t* cmdLine) {
			id_ = id;
			STARTUPINFOW si{ sizeof(si) };
			PROCESS_INFORMATION pi{};

			// const wchar_t*를 CreateProcessW에 전달하기 위해 변환
			// [삭제] wchar_t buffer[MAX_PATH]; wcscpy_s(buffer, cmdLine);
			// [수정] MAX_PATH(260) 고정 스택 버퍼 대신, 길이에 맞춰 힙에 할당되는 가변 버퍼 사용.
			std::wstring buffer = cmdLine;


			//CreateProcessW 구조
			/*
				in: 함수 안으로 데이터를 넣어주는 역할.
				out: 함수가 결과를 담아서 내보내주는 역할.
				optional: 안 넣어도 되는 값입니다.
				BOOL CreateProcessA(
				  [in, optional]      LPCSTR                lpApplicationName,
				  [in, out, optional] LPSTR                 lpCommandLine,
				  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
				  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
				  [in]                BOOL                  bInheritHandles,
				  [in]                DWORD                 dwCreationFlags,
				  [in, optional]      LPVOID                lpEnvironment,
				  [in, optional]      LPCSTR                lpCurrentDirectory,
				  [in]                LPSTARTUPINFOA        lpStartupInfo,
				  [out]               LPPROCESS_INFORMATION lpProcessInformation
				);
				*/ 
			// [수정] CreateProcessW에서 buffer를 buffer.data()로 수정했습니다.
			/*
			왜 std::wstring buffer = cmdLine;이 '제한 없는 버퍼'인가? (메모리 구조의 차이)
			기존 방식과 새로운 방식은 메모리를 할당하는 위치와 방식이 완전히 다릅니다.

			기존 방식 (wchar_t buffer[MAX_PATH]):
			스택(Stack) 메모리에 무조건 260칸(520바이트)짜리 고정 상자를 만듭니다.
			wcscpy_s는 복사하려는 문자열(cmdLine)이 260칸을 1글자라도 넘어서면 버퍼 오버플로우를 막기 위해 프로세스를 강제로 즉시 폭파(Abort)시킵니다.

			새로운 방식 (std::wstring buffer = cmdLine;):
			C++ 표준 문자열 객체는 실행 시점에 cmdLine의 실제 길이를 스스로 측정합니다.
			문자열이 100자든, 1,000자든 그 길이에 딱 맞는 크기의 힙(Heap) 메모리를 동적으로 알아서 할당하여 담아냅니다.
			따라서 길이가 아무리 길어져도 용량 부족으로 프로그램이 터지는 일이 원천적으로 사라집니다.

			buffer -> buffer.data()
			CreateProcessW는 두 번째 인자가 LPWSTR lpCommandLine인데 const가 없는 수정 가능한 메모리를 요구합니다. buffer를 그대로 넣는다면 const wchar_t*(읽기 전용 포인터)가 반환되어 전달이 불가합니다. buffer.data()는 stdLLwstring 내부의 수정 가능한 원본 메모리 주소를 반환합니다.
			*/
			if (!CreateProcessW(NULL, buffer.data(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
				state_ = WinKernel::Types::WorkerState::Crashed;
				return false;
			}

			hProcess_ = pi.hProcess;
			hThread_ = pi.hThread;
			processId_ = pi.dwProcessId; //dw = Double Word: 부호 없는 32bit 정수
			state_ = WinKernel::Types::WorkerState::Running;
			return true;
		}

		// 프로세스 생존 확인
		bool IsRunning() const {
			if (hProcess_ == NULL) return false;

			DWORD exitCode = 0;
			if (GetExitCodeProcess(hProcess_, &exitCode)) {
				return exitCode == STILL_ACTIVE;			//STILL_ACTIVE: 프로세스 실행 중 상태
			}
			return false;
		}

		// 프로세스 종료 대기
		bool Wait(DWORD timeoutMs = INFINITE) {
			if (hProcess_ == NULL) return false;

			DWORD waitResult = WaitForSingleObject(hProcess_, timeoutMs);
			if (waitResult == WAIT_OBJECT_0) {				//WAIT_OBJECT_0: 대기하던 대상이 정상적 종료함을 확인. WaitForSingleObject로 막은 스레드를 풀고 다음 코드를 실행하라.
				state_ = WinKernel::Types::WorkerState::Finished; // main에서 완료된 워커이면 continue할 수 있도록 상태를 변경합니다.
				return true;
			}
			// WAIT_TIMEOUT 등 대기 시간 초과
			return false;
		}

		// 프로세스 강제 종료
		bool Kill(UINT exitCode = 1) {
			if (hProcess_ == NULL) return false;

			if (TerminateProcess(hProcess_, exitCode)) {
				state_ = WinKernel::Types::WorkerState::Crashed;
				return true;
			}
			return false;
		}

		void Close() {
			if (hThread_) {
				CloseHandle(hThread_);
				hThread_ = NULL;
			}
			if (hProcess_) {
				// Close()가 프로세스 핸들을 닫지 않습니다. (핸들 누수)
				// [수정] CloseHandle(hProcess_);추가.
				CloseHandle(hProcess_);
				hProcess_ = NULL;
			}
			state_ = WinKernel::Types::WorkerState::Finished;
		}

		// WokerProcess: Windows 운영체제의 원시적인 자원(HANDLE, PID)을 C++ 객체지향의 형태로 안전하게 포장해놓은 프로세스 관리 대리인.
		WorkerProcess& operator=(WorkerProcess&& other) noexcept { // WorkerProcess&& other에서 &&란? std::move로 인해 곧 파괴될 임시 객체를 참조합니다.
			// 1. 자기 자신에게 대입하는지 확인 (w = std::move(w) 방지)
			if (this != &other) {
				// [삭제]
				// if (hProcess_ != INVALID_HANDLE_VALUE) {
				// 	CloseHandle(hProcess_);
				// }
				// if (hThread_ != INVALID_HANDLE_VALUE) {
				// 	CloseHandle(hThread_);
				// }
				// [수정] 내가 기존에 들고 있던 프로세스 핸들이 있다면 먼저 닫기 (Close 함수 활용 또는 nullptr 검사)
				Close();

				// 3. other(새 워커)의 자원과 상태를 내 것으로 훔쳐오기 (소유권 이전)
				id_ = other.id_; // [추가]
				hProcess_ = other.hProcess_;
				hThread_ = other.hThread_;
				processId_ = other.processId_;
				state_ = other.state_;
				// (주의: 만약 WorkerProcess 안에 다른 멤버 변수가 더 있다면 여기에 똑같이 추가해 주세요)

				// 4. other(새 워커)는 빈 껍데기로 초기화하여, 소멸될 때 핸들이 닫히지 않도록 보호
				// [삭제]-아래 2line
				// other.hProcess_ = INVALID_HANDLE_VALUE;
				// other.hThread_ = INVALID_HANDLE_VALUE;

				//수정
				other.id_ = 0;
				other.hProcess_ = nullptr;
				other.hThread_ = nullptr;
				other.processId_ = 0;
				other.state_ = WinKernel::Types::WorkerState::Idle;	// 이동 생성자와 동일한 센티널(Idle)로 통일
			}
			return *this; // this: 자기 자신의 메모리 주소(포인터), *this: 포인터가 가리키는 자기 자신(객체 실체)
		}

		//상태 확인
		DWORD GetPID() const { return processId_; }
		// [추가] Manager의 Hang 감지(GetProcessTimes)/종료코드 조회용 프로세스 핸들 접근자
		HANDLE GetProcessHandle() const { return hProcess_; }
		//WinKernel::Types::WorkerState는 반환 타입입니다.
		WinKernel::Types::WorkerState GetState() const { return state_; }
	};
}