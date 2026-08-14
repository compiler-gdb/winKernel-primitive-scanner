// 변조한 데이터를 실제 타깃을 대상으로 넣는 전송 장치.

module;
#include <Windows.h>
#include <string>
#include <vector>
#include <iostream>
#include <format>

export module WinKernel.Driver;

export namespace WinKernel::Driver{

	class DriverController{
	private:
		HANDLE hDevice_;
		std::wstring deviceName_;

	public:
		// RAII 패턴을 적용하여 드라이버 심볼릭 링크를 열기.
		// explicit: 개발자가 명시적으로 직접 적었을 때만 변환하라고 강제.
		explicit DriverController(const std::wstring& symLinkName) 
			: deviceName_(symLinkName), hDevice_(INVALID_HANDLE_VALUE) {
			
			// CreateFile 함수는 일반 파일을 열 때 사용합니다. 하지만 커널 드라이버를 타겟으로 삼고 있습니다. 윈도우가 드라이버를 열고자하는 의도를 알게 하기 위해서는 \\.\이라는 기호를 붙히도록 약속되어 있습니다.
			std::wstring fullDeviceName = std::format(L"\\\\.\\{}", deviceName_);

			hDevice_ = CreateFileW( // HANDLE 획득
				fullDeviceName.c_str(),		  // c_str: 윈도우 운영체제의 근간은 C언어로 되어 있습니다. C언어가 wstring이라는 최신 C++ 객체를 이해하기에는 어렵기에 원시적인 글자들의 메모리 포인터만 골라서 윈도우 API에 전달합니다.
				GENERIC_READ | GENERIC_WRITE,
				FILE_SHARE_READ | FILE_SHARE_WRITE,	// [수정] - 공유 모드 0 (독점)이 아닌 여러 워커 프로세스가 동시에 접근할 수 있도록 공유를 허용합니다.
				nullptr,							// 보안 및 상속 설정. 이 핸들(통로)의 보안 수준 설정 및 자식 프로그램에게 물려줄 것인지. nullptr: 시스템 기본 보안을 따르고 자식에게 HANDLE을 물려주지 않습니다.
				OPEN_EXISTING,
				FILE_FLAG_OVERLAPPED,				// [수정] 비동기(Overlapped) 모드 활성화 
				nullptr								// 새로운 파일을 만들 때 디자인(속성)을 배껴올 원본(템플릿)이 있는지. 이미 존재하는 드라이버를 열람할 것이기에 nullptr.
			);
		}

		~DriverController() {
			if (hDevice_ != INVALID_HANDLE_VALUE) { // '정상적으로 프로그램이 돌아간다면' 이라는 의미입니다.
				CloseHandle(hDevice_);
			}
		}

		bool IsConnected() const {
			return hDevice_ != INVALID_HANDLE_VALUE;
		}

		// IOCTL 패킷 전송.
		bool SendIoctl(DWORD ioctlCode, const std::vector<uint8_t>& inputBuffer, std::vector<uint8_t>& outputBuffer, DWORD timeoutMs = 500) {
			if (!IsConnected()) return false;

			// [추가] 비동기 통신 상태를 추적할 OVERLAPPED 구조체 및 이벤트 생성
			OVERLAPPED ov = { 0 }; // OVERLAPPED 구조체.
			ov.hEvent = CreateEventW(	// hEvent: OVERLAPPED 구조체 안에 미리 만들어져 있는 HANDLE 타입 변수. ov라는 비동기 구조체 안에 있는 알람 벨 핸들 변수라고 이해.
				nullptr,	// 기본 보안을 적용하며, 자식 프로세스에게 이 알람 벨을 물려주지 않음
				TRUE,		// 수동 리셋(Manual Reset) 모드. 한번 울린 알람은 개발자가 끌 때까지 울림 유지 (Overlapped 필수)
				FALSE,		// 처음 만들었을 때는 꺼진 상태(Unsignaled)로 시작
				nullptr		// 이름 없는 익명 알람 벨 (프로세스 내부 전용. 다른 프로세스와 이름 공유할 필요 없는 경우)
			);
			if (ov.hEvent == nullptr) return false; // ov.hEvent == nullptr은 hEvent를 정상적으로 만들지 못했는가?라는 의미입니다.

			DWORD bytesReturned = 0;

			BOOL result = DeviceIoControl(		// CreateFileW로 타겟 커널 드라이버로 연결되는 통신 파이프라인을 열고 그 통로를 이용할 수 있는 HANDLE을 얻었습니다. DeviceIoControl은 HANDLE을 통해 커널 드라이버에게 변조된 입력 데이터와 명령 코드를 전송합니다.
				hDevice_,													// 타깃 드라이버 핸들
				ioctlCode,													// 호출할 IOCTL 함수 코드
				(LPVOID)inputBuffer.data(),									// Mutator가 비틀어버린 입력 데이터
				static_cast<DWORD>(inputBuffer.size()),						// 입력 데이터 크기
				outputBuffer.empty() ? nullptr : outputBuffer.data(),		// 결과를 받을 버퍼 (존재 시)
				static_cast<DWORD>(outputBuffer.size()),					// 결과 버퍼 크기
				&bytesReturned,												// 실제 반환된 바이트 수
				&ov															// [수정] nullptr 대신 비동기 객체 주소 전달
			);
			
			bool success = false;
			
			//ov에는 무엇이 담겨있는가
			/*
			1. hEvent (이벤트 핸들)
				- 유저 모드와 커널이 신호를 주고 받는 매개체입니다.
				- CreateEventW()로 생성해서 넣어준 값.
				- 커널이 드라이버 처리를 끝내면 hEvent에게 신호를 주고, WaitForSingleObject로 대기하던 워커가 신호를 보고 깨어납니다.

			2. Internal (커널 상태 코드)
				- 처음 ERROR_IO_PENDING(작업중) 상태였다가, 커널이 작업을 마치면 여기에 성공 여부를 덮어씁니다.

			3. InternalHigh (전송된 바이트 수)
				- 커널 작업이 완료되었을 때, 실제로 드라이버가 유저 모드로 몇 바이트를 반환했는지 크기를 기록합니다.
				- GetOverlappedResult() 함수가 이 값을 읽어서 우리에게 알려줍니다.
			*/

			// 3. 결과 대기 및 타임아웃(Hang) 처리
			if (result) {
				// 운 좋게 즉시 처리가 끝난 경우
				success = true;
			}
			// GetLastError: 현재 스레드에서 직전에 실행된 Windows API 함수가 남긴 "가장 최근의 상세 에러 번호"를 조회합니다.
			// ERROR_IO_PENDING: 비동기 작업이 정상적으로 커널 대기열에 접수되어 백그라운드에서 처리 중임을 의미하는 윈도우 정식 상태코드(997)입니다.
			else if (GetLastError() == ERROR_IO_PENDING) {  // 정상적으로 비동기 통신이 시작된 경우
				// 정상적으로 커널이 비동기 처리 중인 경우, 유저모드에서 스톱워치(timeoutMs) 작동
				DWORD waitResult = WaitForSingleObject(ov.hEvent, timeoutMs); // WaitForSingleObject: 유저 모드 스레드가 커널의 결과를 기다립니다. ov.Event라면 ov에 대한 hEvent만을 기다립니다.

				if (waitResult == WAIT_TIMEOUT) {	// WAIT_TIMEOUT: WaitForSingleObject에 설정한 시간이 다 돌 때까지 알람 벨이 울리지 않았을을 의미하는 Windows API의 약속된 상수 값입니다.
					// 커널이 무한 루프에 빠졌다고 판단하고 I/O 요청을 강제 취소 (워커 스레드 구출)
					CancelIo(hDevice_);
					success = false;
				}
				// 제한 시간 내에 커널이 정상적으로 응답을 준 경우
				else if (waitResult == WAIT_OBJECT_0) {
					// GetOverlappedResult: 비동기(Overlapped) I/O 작업이 끝난 후 실제 최종 결과(성공/실패)와 드라이버가 반환한 실제 크기를 가져오는 API입니다.
					if (GetOverlappedResult(hDevice_, &ov, &bytesReturned, FALSE)) { // TRUE: 커널 작업이 안 끝났다면 끝날 때까지 함수 내부에서 대기. FALSE: 기다리지 않고 끝났는가 아닌가 확인하고 빠져나감. 
						success = true;
					}
					/*
					마스터 프로세스는 워커 프로세스에서 전송한 패킷에 대한 문제가 발생한 것과 프로세스 자체가 죽은 것을 구분하지 못합니다. 
					워커 프로세스가 자체적으로 자신의 작업을 검사할 수 있다면 워커 프로세스는 살아있다는 의미고, 0.5초가 넘어가면 다음 작업을 실행합니다.
					이는 마스터 프로세스가 워커 프로세스가 죽은 것과 작업에 차질이 생긴 것을 구분하는 것과 유사한 효과를 기대할 수 있습니다.
					프로세스 재생성 오버헤드는 0초로 시간을 줄일 수 있습니다.
					*/
				}
			}
			CloseHandle(ov.hEvent);
			return success;
		}
	};
}