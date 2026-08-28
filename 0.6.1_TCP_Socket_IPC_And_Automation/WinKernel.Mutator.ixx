// IOCTL 패킷 구조체의 포인터/크기 필드를 변조하는 알고리즘 담당.
// IOCTL: 유저 모드 프로그램이 커널 모드 드라이버(.sys)에게 "이 작업 처리해달라" 요청할 때 사용하는 요청 포맷입니다.

// 퍼징 패킷이 엉뚱해서 드라이버가 제대로 인식하지 않으면 해당 파일에 문제가 존재한다고 판단할 수 있습니다.

module;
#include <vector>
#include <cstdint> //uint8_t, uintptr_t 등
#include <random>
#include <cstring>
#include <iterator> // 어떤 종류의 자료주조든 상관없이 통일된 방식으로 데이터를 처음부터 끝까지 순회할 수 있는 반복자(iterator)를 제공합니다.

export module WinKernel.Mutator;

export namespace WinKernel::Mutator {

	// Interger OverFlow/Underflow 유도용 경계값 상공 배열
	constexpr uint32_t BOUNDARY_VALUES_32[] = {
		0x00000000, // INT_ZERO
		0x00000001, // INT_ONE
		0x7FFFFFFF, // INT32_MAX
		0x80000000, // INT32_MIN
		0xFFFFFFFF  // UINT32_MAX / -1
	};

	class MutatorEngine {
	private:
		std::mt19937 rng_; // Mersenne Twister 알고리즘 사용. 32bit 무작위 정수 생성. rand는 0~32767 범위의 정수만 생성하지만, mt19937은 0~2^32-1 범위의 정수를 생성합니다. rand는 무작위 패턴의 품질이 떨어져 특정 순서나 주기가 쉽게 반복되고 멀티 스레드 환경에서 안전하지 않습니다. mt19937은 난수 품질이 높고 멀티 스레드 환경에서도 안전합니다.
	
	public:
		// 시드를 외부에서 지정 가능하도록 성계하여 재현성 확보. 동일한 시드로 초기화하면 동일한 난수 시퀀스를 생성하기 때문입니다.
		// random_device는 실행할 때마다 컴퓨터의 예측 불가능한 상태를 기반으로 매번 완전히 다른 무작위 시드 1개를 얻습니다. mt19937은 시드 값이 같으면 매번 100% 같은 수열의 난수만 생성합니다. 따라서 random_device로 얻은 시드 값으로 mt19937을 초기화하면, 실행할 때마다 완전히 다른 난수 시퀀스를 생성할 수 있습니다.
		explicit MutatorEngine(uint32_t seed = std::random_device{}()) // std::random_device rd{} 같이 변수를 선언하는 것과는 다릅니다. 현재의 방식은 메모리에 이름 없는 임시 객체를 새로 만듭니다.
			//explicit이 뭐고 왜 쓰는가
			/*
			// 1. 실수를 했다고 가정 하겠습니다. 객체 전달 위치에 정수(1024) 등 원시 타입 값을 잘못 전달했다고 가정합니다. ex) MutatorEngine engine = 1024;
			// 2. explicit이 없으면 컴파일러가 현재 함수 '스택(Stack)'에 1회용 임시 객체를 몰래 만듭니다.
			// 3. 임시 객체 생성자(MapViewOfFile)가 실행되어 가상 주소 연결이 생성됩니다 (내 프로세스의 가상 주소 공간에 OS가 실제 물리 RAM 메모리를 연결함).
			// 4. 해당 문장(;)이 끝나는 즉시 스택의 임시 객체가 파괴되며 소멸자가 자동 실행됩니다.
			// 5. 소멸자의 UnmapViewOfFile()이 내 프로세스의 가상 주소 매핑을 삭제합니다. (OS의 실제 물리 RAM 메모리는 남아있지만, 접근할 수 있는 가상 주소 길이 끊김)
			// 6. 끊어진 주소로 데이터 접근 시 0xC0000005 (Access Violation) 예외 발생.
			//
			// 생성자에 explicit을 선언하여 암시적 형변환을 차단하면, 실행 중 터지는 크래시를 코딩 시점의 '컴파일 에러(빨간 줄)'로 즉시 감지하여 수정할 수 있게 됩니다.
			*/
			: rng_(seed) {} // 여기서의 {}는 MutatorEngine의 Body입니다.

		void SetSeed(uint32_t seed) {
			rng_.seed(seed);
		}

		// 무작위 1개 바이트를 선택하여 1비트를 반전시킵니다.(비트 플립) - 플래그 및 비트마스크 오염. 권한 변수 오염 및 암호화/압축 헤더의 미세한 파손 유도
		void MutateBitFlip(std::vector<uint8_t>& buffer) {
			if (buffer.empty()) return;	// 버퍼가 비어있으면 아무것도 하지 않고 종료합니다.

			// uniform_int_distribution은 지정한 범위 안의 모든 정수가 동일한 확률(균등 분포)로 나오도록 난수를 변환해 줍니다.
			std::uniform_int_distribution<size_t> byteDist(0, buffer.size() - 1); // 버퍼의 크기 범위 내에서 무작위 바이트 인덱스를 선택합니다.
			std::uniform_int_distribution<uint16_t> bitDist(0, 7); // 8개의 비트 중에서 0~7 범위의 정수를 균등하게 선택합니다. 0~255인 uint8_t가 아닌 uint16_t를 사용하는 이유는 uniform_int_distribution의 템플릿 매개변수로 uint8_t를 사용할 수 없기 때문입니다. (C++ 표준 라이브러리의 제한)

			// size_t로 지정한 이유는 buffer.size()의 반환 타입과 일치하며, 만약 buffer.size()가 매우 큰 경우에도 안전하게 처리할 수 있습니다. (32bit 환경에서 4GB 이상 버퍼를 다루는 경우를 대비)
			size_t targetByte = byteDist(rng_); // rng_라는 난수 생성기에서 무작위 난수를 얻고 uniform_int_distribution을 사용한 byteDist를 이용하여 특정한 수가 많이 나오지 않도록 균등하게 분포시킵니다.
			uint8_t targetBit = bitDist(rng_);  // 몇 번째 비트를 반전시킬지 결정합니다. 0~7 범위의 정수 중 하나를 무작위로 선택합니다.

			/*
			1. (1 << targetBit) : 1(00000001)을 targetBit만큼 왼쪽으로 시프트하여 해당 비트 위치에 1을 설정합니다. 예를 들어 targetBit가 3이면 (1 << 3)은 00001000이 됩니다.
			2. ^= : XOR 연산(비트 반전)을 수행합니다. XOR 연산은 두 비트가 다를 때 1을 반환하고, 같으면 0을 반환합니다. 마스크에서 1이 위치한 비트만 값이 반전되고 0이 위치한 비트는 그대로 유지됩니다.
			*/
			buffer[targetByte] ^= (1 << targetBit); // 랜덤하게 선택한 index를 buffer에 적용하여 해당 바이트의 특정 비트를 반전시킵니다. 특정 bit란 위의 bitDist(rng_)로 결정한 것입니다.
		}

		// 무작위 1개 바이트를 무작위 값으로 변경합니다. (바이트 오버라이트) - Enum 및 Opcode 오염. CMD_READ(1) 등의 명령 코드를 미정의 값으로 바꿔 예외처리 미흡 유도를 합니다.
		void MutateByteOverwrite(std::vector<uint8_t>& buffer) {
			if (buffer.empty()) return;

			std::uniform_int_distribution<size_t> byteDist(0, buffer.size() - 1);
			std::uniform_int_distribution<uint16_t> valdis(0, 255);

			size_t targetByte = byteDist(rng_);
			// 0~255 범위의 무작위 값을 선택하여 해당 바이트를 덮어씁니다. 메모리에서 1byte의 크기를 가진 채로 그 안에서 0~255 범위의 값을 가지는 것입니다. ex) 5 -> 0000 0101
			// buffer를 생성했을 때 uint8_t 타입으로 생성했습니다. uint16_t를 그대로 유지한다면 0~255 범위의 값이 들어오더라도 컴파일러는 1byte에 2byte를 넣으려고 한다고 이해합니다. static_cast을 이용해서 uint8_t로 형변환을 하면 경고가 사라집니다.
			buffer[targetByte] = static_cast<uint8_t>(valdis(rng_));
		}

		// 무작위 위치에 4byte 경계값을 덮어쓰기 (경계값 주입) - 정수 연산 및 메모리 할당 버그 유도. 0xFFFFFFFF 주입으로 정수 오버플로우 유도, 0x00000000 주입으로 0으로 나누기 유도, 0x7FFFFFFF 주입으로 INT32_MAX 오버플로우 유도 등
		// 비트 플립과 바이트 오버라이트와 경계값 주입을 동시에 사용하는 것은 비트 플립만 쓰면 정수 오버플로우를 유발할 4byte 경계값을 만들 확률이 극히 떨어지고 경게값 주입만 쓰면 1bit짜리 플래그 변수 하나만 살짝 뒤집어서 터뜨리는 섬세한 버그를 못잡습니다.
		void MutateBoundaryValue(std::vector<uint8_t>& buffer) {
			if (buffer.size() < sizeof(uint32_t)) return;

			//왜 4byte씩 하는가?
			/*
			1. 프로그램의 중요한 부분들의 규격은 대부분 4byte입니다. 파일 크기, 이미지 가로/세로 길이, 네트워크 패킷 데이터 양, 메모리 할당 크기, 반복문 횟수 등 핵심적인 숫자의 단위가 4byte(int, uint32_t)입니다.
			2. 1byte씩 찔러서는 치명적인 버그 숫자를 만들지 못합니다. 
			*/
			std::uniform_int_distribution<size_t> posDist(0, buffer.size() - sizeof(uint32_t));

			// BOUNDARY_VALUES_32: 버그를 유발하기 좋은 32bit 극단적 숫자(경계값)들을 모아둔 상수 배열.
			std::uniform_int_distribution<size_t> valDist(0, std::size(BOUNDARY_VALUES_32) - 1);

			size_t targetPos = posDist(rng_);
			uint32_t boundaryVal = BOUNDARY_VALUES_32[valDist(rng_)];

			// *(uint32_t*)&buffer[offset] = value 같이 포인터 대입하지 않고 memcpy를 사용하는 것은 성능 오버헤드 외 별칭 규칙, 메모리 정렬 예외 방지 등의 이유가 있습니다.
			std::memcpy(buffer.data() + targetPos, &boundaryVal, sizeof(uint32_t));
		}

		void Mutate(std::vector<uint8_t>& buffer) {
			if (buffer.empty()) return;

			std::uniform_int_distribution<int> stratDist(0, 2);
			int strategy = stratDist(rng_);

			switch (strategy) {
			case 0: MutateBitFlip(buffer); break;
			case 1: MutateByteOverwrite(buffer); break;
			case 2: MutateBoundaryValue(buffer); break;
			}
		}
	};
}