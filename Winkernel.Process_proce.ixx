//자식 프로세스의 생성, 대기, 강제 종료 생명주기 관리.
//자식 프로세스가 안떠서 멀티프로세싱이 안되면 해당 파일에 문제가 존재한다고 판달할 수 있습니다.

module;
#include <windows.h>
#include <vector>
#include <iostream>

import WinKernel.Types;

export module WinKernel.Process;

export namespace WinKernel {
	namespace Process {

		struct WorkerInfo { //워커 프로세스 정보 관리 구조체
			DWORD id;
			HANDLE hProcess;
			HANDLE hThread;
			DWORD processId;
			WinKernel::Types::WorkerState state;
		};

		//WorkerInfo& outInfo
		//outInfo: 관례적으로 함수 내부에서 값을 채워서 밖으로 꺼내줄 목적의 변수에 붙이는 이름.
		// 성공 실패 여부를 리턴하고 생성된 워커에 대한 자세한 정보는 outInfo라는 인자를 통해 원본에 직접 적어준다는 의미.
		bool SpawnWorkerProcess(DWORD workerId, WorkerInfo& outInfo) {
			/*
			STARTUPINFOW: 새로운 프로세스를 실행할 때 어떤 모양이나 창 상태로 시작할 지 설정값을 담는 구조체.
			ex) 창을 최소화 상태로 켤지, 특정 화면 위치에 띄울지, 표준 입출력을 어디로 연결할지 등.
			끝에 붙은 W는 Wide character 버전을 의미합니다. (UTF-16, 2byte)

			PROCESS_INFORMATION: 운영체제가 프로세스를 생성하고 난 뒤, 방금 만든 프로세스에 대한 결과 정보를 받아오는 구조체
			*/

			//si와 pi 뒤에 {}는 무엇인가?
			//모든 멤버 변수를 0으로 초기화하겠다.
			STARTUPINFOW si{};
			PROCESS_INFORMATION pi{};

			//.cb: STARTUPINFOW 내부에 정의되어 있는 멤버 변수.Count of Bytes 즉, 구조체 전체의 크기를 의미합니다.
			si.cb = sizeof(si);
		}
	}
}