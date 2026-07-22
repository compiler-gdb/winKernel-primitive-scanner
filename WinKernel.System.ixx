//OS 및 하드웨어 스펙 조회
//코어 수 스캔 방식이나 시스템 정보를 잘못 가져올 경우 해당 파일에 문제가 존재한다고 판단할 수 있습니다.

module;
#include <windows.h>

export module WinKernel.System;

export namespace WinKernel {
	namespace System {
		DWORD GetLogicalCoreCount() {
			SYSTEM_INFO sysInfo;
			GetSystemInfo(&sysInfo);
			return sysInfo.dwNumberOfProcessors; //현재 시스템에서 사용 가능한 논리 프로세서의 총 개수를 나타내는 32비트 정수(DWORD) 값
		}
	}
}