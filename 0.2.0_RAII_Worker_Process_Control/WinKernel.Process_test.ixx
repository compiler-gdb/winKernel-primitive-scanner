//자식 프로세스의 생성, 대기, 강제 종료 생명주기 관리.
//자식 프로세스가 안떠서 멀티프로세싱이 안되면 해당 파일에 문제가 존재한다고 판달할 수 있습니다.

module;
#include <Windows.h>

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
		// 인자로 전달받을 other는 private에서 지정한 WorkerProcess의 형식을 따릅니다.
		WorkerProcess(WorkerProcess&& other) noexcept
			: id_(other.id_), hProcess_(other.hProcess_), hThread_(other.hThread_),
			processId_(other.processId_), state_(other.state_) {
			other.hProcess_ = NULL;
			other.hThread_ = NULL;
			other.state_ = WinKernel::Types::WorkerState::Idle;
		}

		//자식 워커 프로세스를 실행합니다.
		//STARTUPINFOW에서 sizeof(si)를 꼭 붙혀야 하나?
		//윈도우가 프로그램을 띄울 때 참고하는 설정 데이터 묶음인 STARTUPINFOW는 OS 버전별로 기능이 추가되며 크기가 다릅니다. 어디까지 읽을지 판단할 수 있게 되며 뒤에 쓰래기 값을 무시하게 됩니다.
		bool Launch(DWORD id, const wchar_t* cmdLine) {
			id_ = id;
			STARTUPINFOW si{ sizeof(si) };
			PROCESS_INFORMATION pi{};

			// const wchar_t*를 CreateProcessW에 전달하기 위해 변환
			wchar_t buffer[MAX_PATH];
			wcscpy_s(buffer, cmdLine);

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
				*/ //CreateProcessW 구조
			if (!CreateProcessW(NULL, buffer, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
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
				return exitCode == STILL_ACTIVE;
			}
			return false;
		}

		// 프로세스 종료 대기
		bool Wait(DWORD timeoutMs = INFINITE) {
			if (hProcess_ == NULL) return false;

			DWORD waitResult = WaitForSingleObject(hProcess_, timeoutMs);
			if (waitResult == WAIT_OBJECT_0) {
				state_ = WinKernel::Types::WorkerState::Finished;
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
				hProcess_ = NULL;
			}
			state_ = WinKernel::Types::WorkerState::Finished;
		}

		//상태 확인
		DWORD GetPID() const { return processId_; }
		//WinKernel::Types::WorkerState는 반환 타입입니다.
		WinKernel::Types::WorkerState GetState() const { return state_; }
	};
}