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

			hDevice_ = CreateFileW(			  // CreateFileA와의 차이는 A는 영어 전용, W는 다국어/유니코드 전용입니다. (A: ANSI, W: Wide)

				fullDeviceName.c_str(),		  // c_str: 윈도우 운영체제의 근간은 C언어로 되어 있습니다. C언어가 wstring이라는 최신 C++ 객체를 이해하기에는 어렵기에 원시적인 글자들의 메모리 포인터만 골라서 윈도우 API에 전달합니다.
				GENERIC_READ | GENERIC_WRITE, // 읽기/쓰기 권한 요청
				0,							  // 공유 모드 0 (독점)
				nullptr,					  // 보안 및 상속 설정. 이 핸들(통로)의 보안 수준 설정 및 자식 프로그램에게 물려줄 것인지. nullptr: 시스템 기본 보안을 따르고 자식에게 HANDLE을 물려주지 않습니다.
				OPEN_EXISTING,				  // 이미 존재하는 드라이버만 열람.
				FILE_ATTRIBUTE_NORMAL,		  // 아무런 특수 옵션도 없는 상태로 열라. 숨김 파일 또는 읽기 전용 등의 속성 x
				nullptr						  // 새로운 파일을 만들 때 디자인(속성)을 배껴올 원본(템플릿)이 있는지. 이미 존재하는 드라이버를 열람할 것이기에 nullptr.
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
		bool SendIoctl(DWORD ioctlCode, const std::vector<uint8_t>& inputBuffer, std::vector<uint8_t>& outputBuffer) {
			if (!IsConnected()) return false;

			DWORD bytesReturned = 0;

			BOOL result = DeviceIoControl(
				hDevice_,													// 타깃 드라이버 핸들
				ioctlCode,													// 호출할 IOCTL 함수 코드
				(LPVOID)inputBuffer.data(),									// Mutator가 비틀어버린 입력 데이터
				static_cast<DWORD>(inputBuffer.size()),						// 입력 데이터 크기
				outputBuffer.empty() ? nullptr : outputBuffer.data(),		// 결과를 받을 버퍼 (존재 시)
				static_cast<DWORD>(outputBuffer.size()),					// 결과 버퍼 크기
				&bytesReturned,												// 실제 반환된 바이트 수
				nullptr														// 비동기 I/O 미사용
			);

			return result == TRUE;
		}
	};
}