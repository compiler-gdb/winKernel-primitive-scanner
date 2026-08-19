module;
#include <Windows.h>
#include <vector>
#include <cstdint>
#include <string>
#include <optional>

export module WinKernel.Engine;

export namespace WinKernel::Engine {

	// 스캔할 메모리 구역 정보
	struct MemoryRegion {
		uintptr_t baseAddress{ 0 }; //uintptr_t는 포인터 주소값을 담을 수 있는 부호 없는 정수 타입. 64비트 기준 8byte 정수. void*는 덧셈/뺄셈 연산 금지이기에 사용합니다.
		size_t regionSize{ 0 };
		DWORD protect{ 0 };
	};

	// Array of Bytes 스캔용 패턴 구조체
	struct Pattern {
		std::vector<uint8_t> bytes; //uint8_t는 부호없는 1byte 정수
		std::string mask;			//xxx??xx (?는 와일드 카드)를 위해서 선언
	};

	class MemoryScanner {
	private:

		//std::vector<uint8_t>라고 한다면 데이터를 한 번에 읽어오지만 변수에 1byte 단위로 정리하여 저장합니다.
		//scanBuffer_ 뒤의 {}는 기본 값으로 초기화 하라는 의미입니다. vector 뒤에 사용할 경우 요소가 0개인 빈 상태로 초기화 됩니다.
		//inline static: static만으로 정의하려 한다면 WinKernel.Engine에서 1개, main.cpp에서 이것을 사용하려고 한다면 2개로 인식되어 컴파일 에러가 발생했습니다.
		//static의 경우 객체를 여러개 만들어도 이 변수는 메모리 공간에 1개만 존재하며 모든 객체가 공유하는 것이기 때문입니다. 하지만 inline static으로 선언한다면 Engine 쪽에서만 정의해도 됩니다.
		std::vector<uint8_t> scanBuffer_{}; //메모리를 매번 동적 할당하지 않고 재사용하기 위한 내부 버퍼.

		// 1차/2차 스캔 결과를 보관할 객체 내 상태 변수. 멀티 프로세스 내에서 MemoryScanner 객체 생성 추 반환.
		std::vector<uintptr_t> candidateAddresses_{};

		static bool MatchesPattern(const uint8_t* data, const Pattern& pattern) { //static은 객체 생성을 안해도 메모리에 항상 고정되어 존재하는 것을 의미합니다.
			for (size_t i = 0; i < pattern.bytes.size(); ++i) {

				//와일 카드인 경우 바이트 비교를 스킵합니다.
				if (pattern.mask[i] == '?') {
					continue;
				}
				if (data[i] != pattern.bytes[i]) {
					return false;
				}
			}
			return true;
		}

	public:

		static std::vector<MemoryRegion> EnumerateReadableRegions(HANDLE hProcess) {
			std::vector<MemoryRegion> regions;
			
			// 메모리 탐색 시 0x0부터 탐색하도록 세팅합니다.
			// uint8_t*는 타입이며 currentAddress 변수는 uint8_t데이터가 위치한 메모리 주소를 저장하는 포인터 변수입니다.
			uint8_t* currentAddress = nullptr;
			MEMORY_BASIC_INFORMATION mbi{};

			while (VirtualQueryEx(hProcess, currentAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) {

				bool isCommitted = (mbi.State == MEM_COMMIT);
				bool isAccessible = !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS);

				DWORD baseProtect = (mbi.Protect & 0xFF);

				// 읽기 권한 보유 조건을 만족하는 페이지 영역만 수집해야 합니다.mbi.State = MEMCOMMIT 일 것, (mbi.Process & PAGE_NOACCESS) 및(mbi.Protect & PAGE_GUARD)가 아닐 것, PAGE_READONLY PAGE_READWRITE PAGE_EXECUTE_READWRITE 등
				bool isReadable = (baseProtect == PAGE_READONLY) ||
								  (baseProtect == PAGE_READWRITE) ||
								  (baseProtect == PAGE_WRITECOPY) ||
								  (baseProtect == PAGE_EXECUTE_READ) ||
								  (baseProtect == PAGE_EXECUTE_READWRITE) ||
								  (baseProtect == PAGE_EXECUTE_WRITECOPY);

				if (isCommitted && isAccessible && isReadable) {
					MemoryRegion region;
					region.baseAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
					region.regionSize = mbi.RegionSize;
					region.protect = mbi.Protect;

					regions.push_back(region);
				}
				//static_cast: 논리적으로 연결되거나  연관성이 있는 타입끼리 안전하게 변환합니다.
				//reinterpret_cast는 서로 다른 타입을 억지로 엮는 거라면 static_cast는 컴파일 타임에 변환이 가능한 것인지 검사하고 안전하게 바꿔줍니다.
				uint8_t* nextAddress = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize; 

				if (nextAddress <= currentAddress) {
					break;
				}
				currentAddress = nextAddress;
			}
			return regions;
		}

		// AOB 패턴 스캔 (AOB: Array of Bytes의 약자로, 바이트 배열의 줄임말.) 
		// AOB 패턴 스캔은 단순 데이터 값을 찾는게 아니라 프로그램을 구성하는 기계어 코드와 서명을 찾는 것을 의미합니다.
		// ScanValue와 다른 점은 RAM 속에서 숫자 100이 저장된 변수를 찾으려면 ASLR로 인해 프로그램이 실행할 때마다 달라지지만, AOB를 스캔하면 해당 100을 관리하는 어셈블리 명령어의 기계어 바이트 배열을 찾아서 위치가 그대로 유지됩니다. 
		std::vector<uintptr_t> ScanPattern(
			HANDLE hProcess,
			const MemoryRegion& region,
			const Pattern& pattern
		) {
			std::vector<uintptr_t> matchAddresses;

			//패턴이 비어있거나 마스크 길이가 맞지 않으면 중단
			if (pattern.bytes.empty() || pattern.bytes.size() != pattern.mask.size()) {
				return matchAddresses;
			}

			//스캔할 영역이 패턴 크기보다 작으면 스캔 불가 예외처리.
			if (region.regionSize < pattern.bytes.size()) {
				return matchAddresses;
			}

			//재사용 버퍼 크기 조절 및 메모리 할당. 오버하드 최소화.
			//해당 코드에서는 region.regionSize만큼의 크기로 resize를 진행.
			if (scanBuffer_.size() < region.regionSize) {
				scanBuffer_.resize(region.regionSize);
			}
			SIZE_T bytesRead = 0;		// Windows SDK에서 정의해 둔 부호 업는 정수

			//ReadProcessMemory로 대상 영역의 RAM 데이터를 유저 버퍼로 한 번에 복사
			BOOL success = ReadProcessMemory(
				hProcess,
				//reinterpret_cast: 비트 배열은 그대로 둔 채로 컴파일러에게 타입을 재해석하라고 강제 명령합니다.
				//만약 숫자 주소 0x7FF0000 같은 uintptr_t가 있을 때 윈도우 API가 요구하는 포인터 타입(LPCVOID 즉, const void*)으로 변경합니다.
				//이 숫자가 무슨 타입이었든 간에 LPCVOID로 취급하라고 덮어씌우는 겁니다.
				reinterpret_cast<LPVOID>(region.baseAddress), 
				scanBuffer_.data(),
				region.regionSize,
				&bytesRead
			);

			if (!success || bytesRead < pattern.bytes.size()) {
				return matchAddresses;
			}

			// 버퍼 안에서 포인터 연산으로 패턴 매칭 수행 (Syscall 없이 유저모드 ram에서 빠르게 비교)
			const size_t scanLimit = bytesRead - pattern.bytes.size();
			const uint8_t* bufferPtr = scanBuffer_.data();

			for (size_t offset = 0; offset <= scanLimit; ++offset) {
				if (MatchesPattern(bufferPtr + offset, pattern)) {
					//매칭 성공 시 실제 프로세스의 가상 메모리 주소 계산
					matchAddresses.push_back(region.baseAddress + offset); //push_back: vector 배열의 맨 뒤에 새로운 데이터를 1개 추가합니다.
				}
			}
			return matchAddresses;
		}
		
		// 지정된 메모리 영역에서 특정 값(int, float 등) 검색.
		template <typename T>
		static std::vector<uintptr_t> ScanValue(
			HANDLE hProcess,						//ReadProcessMemory로 RAM을 읽어올 대상 프로세스의 핸들.
			const MemoryRegion& region,				//스캔을 수행할 대상 메모리 구역
			T targetValue							//우리가 찾고자 하는 실제 값.
		) {
			std::vector<uintptr_t> matchAddresses;

			//region.regionSize: 스캔할 메모리 구역의 크기(ex 2byte)
			//sizeof(T): 찾고자 하는 데이터 타입의 바이트 크기입니다.
			if (region.regionSize < sizeof(T)) {
				return matchAddresses;
			}

			//.size(): 현재 이 버퍼가 메모리에 확보해 둔 실제 바이트 크기를 가져옵니다.
			//.regionSize(): 특정 구역의 크기를 나타냅니다.
			if (scanBuffer_.size() < region.regionSize) {

			//.resize(): 실제 요소의 개수를 강제로 바꿉니다.
			//예시) region.regionSize가 4096byte인데 나의 scanBuffer_의 크기가 0byte 또는 100byte같은 상태인데 ReadProcessMemory가 4096byte를 강제로 넣으면 메모리 침범 에러가 발생.
			//그렇기 때문에 4096byte를 담을 수 있도록 버퍼의 크기를 미리 넓혀둡니다.
				scanBuffer_.resize(region.regionSize);
			}

			SIZE_T bytesRead = 0;
			BOOL success = ReadProcessMemory(
				hProcess,
				reinterpret_cast<LPCVOID>(region.baseAddress),
				scanBuffer_.data(),
				region.regionSize,
				&bytesRead
			);

			if (!success || bytesRead < sizeof(T)) { //byteRead < sizeof(T)			 ex) ScanValue<double>(...., 100.0)으로 입력했다 가정, 만약 T가 double처럼 8byte인 것이 아닌 그 이하의 값일 경우 완벽한 값 비교가 불가.
				return matchAddresses;
			}

			// RAM 훑는 로직 (1바이트씩 이동하며 targetValue와 같은지 확인)
			const size_t scanLimit = bytesRead - sizeof(T);
			const uint8_t* bufferPtr = scanBuffer_.data();

			for (size_t offset = 0; offset <= scanLimit; ++offset) {
				// 현재 오프셋 위치의 바이트 데이터를 T 타입(int, float 등)으로 해석
				T currentValue = *reinterpret_cast<const T*>(bufferPtr + offset);

				if (currentValue == targetValue) {
					matchAddresses.push_back(region.baseAddress + offset);
				}
			}

			return matchAddresses;
		}

		template <typename T>
		size_t FileterValue(HANDLE hProcess, T targetValue) {
			std::vector<uintptr_t> filteredAddresses;		// 읽기에 성공한다면 해당 주소를 담을 변수입니다.

			//기존 candidateAddresses_에 담긴 주소들에 한하여 재검사
			for (uintptr_t addr : candidateAddresses_) { //candidateAddresses_라는 vector에 들어있는 주소들을 하나씩 꺼내서 addr에 담아달라. Python의 리스트컴프리헨션과 동일한 기능.
				T currentValue{};
				SIZE_T byteRead = 0;

				//해당 주소의 메모리를 ReadProcessMemory로 읽습니다.
				BOOL success = ReadProcessMemory(
					hProcess,
					reinterpret_cast<LPCVOID>(addr),	//addr을 괄호로 감싸는 것은 reinterpret_cast의 문법 규칙입니다.
					&currentValue,						//위에서 만든 currentValue에 ReadProcessMemory가 값을 채워줍니다.
					sizeof(T),
					&byteRead
				);

				//읽기 성공 및 targetValue와 일치한다면 값을 살려둡니다.
				if (success && byteRead == sizeof(T) && currentValue == targetValue) {
					filteredAddresses.push_back(addr);
				}
			}
			//해당 주소들로 candidateAddresses_를 갱신합니다. std::move로 오버헤드 없이 교체합니다.
			candidateAddresses_ = std::move(filteredAddresses);

			//최종적으로 남은 주소의 개수를 반환합니다.
			return candidateAddresses_.size();
		}

		//밖에서 남은 후보 주소들을 조회할 수 있습니다.
		const std::vector<uintptr_t>& GetCandidateAddresses() const {
			return candidateAddresses_;
		}
	};
}