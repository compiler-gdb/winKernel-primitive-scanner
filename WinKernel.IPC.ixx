/*
[마스터 프로세스]
 1. EnumerateReadableRegions로 대상 메모리 구역(MemoryRegion N개) 수집
 2. SharedMemoryManager::Create()로 공유 메모리 할당
 3. MemoryRegion 목록을 공유 메모리의 데이터 영역에 복사
 4. SharedControlHeader.totalRegions = N, currentRegionIndex = 0 초기화
 5. WorkerManager로 N개의 워커 프로세스 실행 (인자로 공유 메모리 이름 전달)

[워커 프로세스 (WorkerProcess)]
 1. SharedMemoryManager::Open()으로 동일한 공유 메모리 연결
 2. while 문 진입:
    size_t idx = header->currentRegionIndex.fetch_add(1); // 락 없이 인덱스 획득
    if (idx >= header->totalRegions) break;               // 전체 구역 처리 완료 시 종료
 3. 공유 메모리에서 regions[idx] 정보를 읽어 MemoryScanner::ScanValue() 수행
 4. 찾아낸 주소를 공유 메모리의 결과 버퍼 영역에 락프리로 기록
*/

module;
#include <Windows.h>
#include <atomic>
// atomic: 일반 변수의 값 변경은 읽은 다음 수정하고 저장을 합니다. 두 개의 프로세스가 동시에 이 작업을 한다면 단계가 꼬여서 데이터가 유실됩니다. atomic은 이 단계들을 하나의 통합된 명령으로 만들어서 다른 프로세스가 읽기만 하고 아직 쓰지 못한 중간 상태에 접근하지 못하게 합니다.
//		   OS 차원의 무거운 잠금(Mutex 등)을 사용하지 않고 CPU 수준에서 가장 빠르게 동기화를 처리해주는 최소 단위 안정장치입니다.
#include <cstdint>
#include <string>

export module WinKernel.IPC;

export namespace WinKernel::IPC {					
	// 공유 메모리 가장 앞에 위치할 락프리 헤더 구조체
	// 왜 하필 구조체로 작성했지?
	/*
	1. 실수 방지: class로 만든다면 유지 보수 중에 가상 함수(virtual)를 추가하거나, 상속 구조를 도입하거나, private 멤버를 섞어 넣을 수 있습니다. 그 순간, 메모리 배치가 깨져 공유 메모리가 오염됩니다.

	2. C++ 표준: 단순 데이터의 연속된 메모리 배치를 나타낼 때는 struct를 사용하고, 메서드나 캡슐화 중심의 객체를 만들 때는 class를 사용하는 것이 관례입니다.
				 struct로 선언하는 것이 곧 '이 구조체는 OOP용 클래스가 아니라 오직 메모리 매핑용 데이터 덩어리다'라는 의도를 명확히 전달합니다.

	3. POD 타입: 공유 메모리에 올리는 구조체는 메모리 레이아웃이 완전히 예측 가능해야 합니다. 만약 virtual 키워드를 사용해 가상 함수를 추가하면, 객체 내부에 가상 함수 테이블 포인터(vptr)가 주입됩니다.
				 vptr이 가리키는 메모리 주소는 프로세스마다 완전히 다르기 때문에, 다른 프로세스에서 공유 메모리를 읽을 때 잘못된 주소를 참조하여 크래시(Crash)가 발생합니다. 따라서 공유 메모리 구조체는 vptr이나 프로세스 종속적인 포인터가 없는 단순 데이터 구조(POD/Standard-Layout)로 유지해야 합니다.
	*/
	struct SharedControlHeader {
		std::atomic<SIZE_T> currentRegionIndex{ 0 }; // 락프리 구역 배분용 원자적 인덱스 (Lock-Free)
		std::atomic<SIZE_T> totalRegions{ 0 };       // 전체 메모리 구역 수
		std::atomic<SIZE_T> totalMatches{ 0 };       // 탐색된 총 결과 주소 수
		DWORD masterPID{ 0 }; // 마스터 프로세스 PID
	};
}