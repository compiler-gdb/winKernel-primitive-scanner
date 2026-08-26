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
		uintptr_t baseAddress{ 0 };
		size_t regionSize{ 0 };
		DWORD protect{ 0 };
	};

	// Array of Bytes 스캔용 패턴 구조체
	struct Pattern {
		std::vector<uint8_t> bytes;
		std::string mask;
	};

	class MemoryScanner {
	private:
		std::vector<uint8_t> scanBuffer_{};
		std::vector<uintptr_t> candidateAddresses_{};

		static bool MatchesPattern(const uint8_t* data, const Pattern& pattern) {
			for (size_t i = 0; i < pattern.bytes.size(); ++i) {
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
			uint8_t* currentAddress = nullptr;
			MEMORY_BASIC_INFORMATION mbi{};

			while (VirtualQueryEx(hProcess, currentAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) {
				bool isCommitted = (mbi.State == MEM_COMMIT);
				bool isAccessible = !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS);
				DWORD baseProtect = (mbi.Protect & 0xFF);

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

				uint8_t* nextAddress = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
				if (nextAddress <= currentAddress) {
					break;
				}
				currentAddress = nextAddress;
			}
			return regions;
		}

		// 1. AOB 패턴 스캔
		std::vector<uintptr_t> ScanPattern(
			HANDLE hProcess,
			const MemoryRegion& region,
			const Pattern& pattern
		) {
			std::vector<uintptr_t> matchAddresses;

			if (pattern.bytes.empty() || pattern.bytes.size() != pattern.mask.size()) {
				return matchAddresses;
			}
			if (region.regionSize < pattern.bytes.size()) {
				return matchAddresses;
			}

			if (scanBuffer_.size() < region.regionSize) {
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

			if (!success || bytesRead < pattern.bytes.size()) {
				return matchAddresses;
			}

			const size_t scanLimit = bytesRead - pattern.bytes.size();
			const uint8_t* bufferPtr = scanBuffer_.data();

			for (size_t offset = 0; offset <= scanLimit; ++offset) {
				if (MatchesPattern(bufferPtr + offset, pattern)) {
					matchAddresses.push_back(region.baseAddress + offset);
				}
			}
			return matchAddresses;
		}

		// 2. 특정 값(int, float 등) 스캔 (static 제거 + 구현부 { } 추가 완료!)
		template <typename T>
		std::vector<uintptr_t> ScanValue(
			HANDLE hProcess,
			const MemoryRegion& region,
			T targetValue
		) {
			std::vector<uintptr_t> matchAddresses;

			if (region.regionSize < sizeof(T)) {
				return matchAddresses;
			}

			if (scanBuffer_.size() < region.regionSize) {
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

			if (!success || bytesRead < sizeof(T)) {
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
	};
}