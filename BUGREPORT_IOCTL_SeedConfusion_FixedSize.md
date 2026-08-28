# 버그 리포트

## 1. 제목
타깃 IOCTL 코드와 뮤테이션 시드(`base_seed`) 파라미터 혼동 및 페이로드 크기 고정으로 인한 퍼징 탐색 무력화(결정론적 100% 크래시)

## 2. Severity
**Critical**
퍼저의 핵심 목적(입력 변이를 통한 미지의 취약점 탐색)이 완전히 무력화되어, 모든 반복이 이미 알려진 단일 취약점만을 100% 확률로 재현하는 상태였다. 새로운 취약점을 발견할 수 없을 뿐 아니라, 크래시 결과의 신뢰도(True Positive/False Positive 판별)를 실증할 방법 자체가 없었다.

## 3. Priority
**P1**
드라이버 연결·워커 스폰·IPC 등 기본 파이프라인은 정상 동작하여 즉시 서비스 중단(P0)은 아니지만, 퍼징 도구로서의 본질적 기능(탐색)을 상실한 상태이므로 다음 스프린트 내 최우선 수정 대상.

## 4. Filename
- `WinKernel.Types.ixx`
- `WinKernel.Worker.ixx`
- `WinKernel.Mutator.ixx`
- `WinKernel.Manager.ixx`
- `main.cpp`
- `monitoring.py`

## 5. Feature
Fuzzing Input Generation — Target IOCTL Selection & Payload Size Mutation

## 6. 개요
HEVD(HackSysExtremeVulnerableDriver)를 대상으로 퍼징 중, 알려진 유효 시드 `0x222003`뿐 아니라 임의로 지정한 `0x222004`에서도 동일하게 BSOD가 발생하는 현상이 관측되었다. 원인 분석 결과 이는 실제 새로운 취약점이 아니라 (a) 호스트 컨트롤러(`monitoring.py`)가 IOCTL 코드와 뮤테이션 시드(`base_seed`)를 혼동하여 실제로는 IOCTL을 바꾸지 못한 채 동일한 `0x222003`을 재타격하고 있었고, (b) 워커가 페이로드 크기를 `4096B`로 고정해 HEVD 커널 스택 버퍼(~2048B)를 매 반복 결정론적으로 초과시켰기 때문임이 확인되었다. 두 결함이 결합되어 "시드/입력과 무관하게 항상 크래시"라는 오해를 유발했다.

## 7. 사전 조건
- HEVD 드라이버가 로드된 Windows VM(VMware Workstation) 환경.
- `monitoring.py`가 `vmrun`으로 워커 exe를 게스트에 주입·실행하고 TCP(51337)로 리포트를 수신하는 정상 파이프라인이 구성되어 있음.
- 워커의 `WinKernel::Constants::TARGET_IOCTL_CODES`가 `{ 0x222003 }` 단일 원소로 하드코딩되어 있고, CLI에서 IOCTL 코드를 오버라이드할 방법이 없음(수정 전 상태).
- 워커의 페이로드 버퍼 크기가 `DEFAULT_BUFFER_SIZE = 4096`으로 고정되어 있음(수정 전 상태).

## 8. 재현 절차
1. `monitoring.py`의 `main()`에서 `base_seed = 0x222004`로 강제 고정한다(디버깅 목적으로 삽입되어 있던 테스트 해킹).
2. 라운드를 실행하면 이 값이 워커 커맨드라인의 `<0xSEED>` 위치 인자로 전달된다.
3. 워커(`WinKernel.Worker.ixx`)는 이 값을 `MutatorEngine`의 RNG 시드로만 사용하고, 실제 전송 IOCTL은 내장 상수 `TARGET_IOCTL_CODES[0] = 0x222003`을 그대로 사용한다.
4. 매 반복 페이로드는 `basePayload(4096, 0x41)` 후 콘텐츠만 변조되고 크기는 항상 4096B로 고정된 채 `DeviceIoControl(0x222003, ...)`이 호출된다.
5. 게스트 BSOD 발생 → `monitoring.py`가 이를 "seed=0x222004에서 크래시"로 보고.

## 9. 실제 결과
- `base_seed`를 `0x222004`로 바꿔도 IOCTL은 여전히 `0x222003`으로 전송되었고, 페이로드는 항상 4096B(임계 초과)였기 때문에 **첫 반복부터 100% 확정적으로 BSOD**가 발생했다.
- 로그상으로는 "0x222004에서도 크래시가 난다"로 보여, HEVD 미정의 코드 영역에서도 크래시가 발생하는 것처럼 오인되었다.
- 크래시 발생 시 실시간 로그에는 페이로드 "크기 범위"(`size=1..8192`류의 설정값)만 출력되고, 실제로 그 반복에서 사용된 단일 크기 값이 표시되지 않아 임계값 분석(디버깅)이 불가능했다.

## 10. 기대 결과
- `base_seed`(뮤테이션 시드)와 타깃 IOCTL 코드는 서로 독립적인 파라미터여야 하며, IOCTL은 명시적으로 지정 가능해야 한다.
- `0x222004`처럼 HEVD의 `IrpDeviceIoCtlHandler` switch-case에 정의되지 않은 코드가 실제로 전송되면, 드라이버의 `default` 분기에서 `STATUS_INVALID_DEVICE_REQUEST`만 반환되고 **크래시가 발생하지 않아야** 한다(음성 케이스).
- 페이로드 크기는 시드에 따라 가변적이어야 하며, 임계 크기 미만에서는 생존, 초과에서는 크래시가 발생해 "크기"라는 축이 실제 퍼징 변수로 기능해야 한다.
- 실시간 크래시 로그에는 해당 케이스에서 실제로 사용된 단일 크기 값이 표기되어야 한다.

## 11. 발생 원인
1. **파라미터 혼동(주원인):** `monitoring.py`가 IOCTL 코드를 지정할 목적으로 뮤테이션 시드 파라미터(`base_seed`)를 재활용(`base_seed = 0x222004 # 테스트를 위한 강제 고정`)했다. 그러나 C++ 워커 파이프라인(`main.cpp` → `WinKernel.Worker.ixx`)에서 이 값은 오직 `MutatorEngine` 시드로만 소비되며, 실제 IOCTL은 `WinKernel.Types.ixx`의 `TARGET_IOCTL_CODES` 상수 배열에서만 읽혔다. IOCTL을 외부에서 주입할 CLI 경로 자체가 존재하지 않았다.
2. **페이로드 크기 고정(부원인):** `WinKernel.Worker.ixx`의 `Run()`이 `constexpr uint32_t fixedSize = DEFAULT_BUFFER_SIZE(4096)`로 모든 반복의 페이로드 크기를 고정했다. HEVD `BUFFER_OVERFLOW_STACK`의 커널 스택 버퍼(~2048B)를 매번 확정적으로 초과했기 때문에, 뮤테이터가 콘텐츠를 아무리 바꿔도 크래시 발생 여부는 항상 동일(=100%)했고, 시드/변이가 결과에 아무런 영향을 주지 못했다.
3. **관측성 부재(진단 지연 요인):** `FuzzReportPacket`의 `declaredSize/actualSize` 필드가 실제로는 반복별 크기를 담을 수 있었음에도, 워커가 고정값(4096)만 채웠고 호스트의 실시간 `[SAVED:...]` 로그에도 이 필드가 출력되지 않아, 문제를 크기 축에서 재구성하는 데 추가 계측이 필요했다.

## 12. 해결 방법
1. **IOCTL/시드 파라미터 분리:**
   - `main.cpp`(워커·마스터 모드 양쪽)에 `--ioctl 0xNNN`(반복 지정 가능) 및 `--ioctl-random` CLI 플래그를 추가.
   - `WinKernel.Worker.ixx::Run()`에 `ioctlOverride` 인자를 추가하여, 주입값이 있으면 그것을, 없으면 기존 내장 목록을 사용하도록 분기.
   - `WinKernel.Manager.ixx`가 자식 워커 커맨드라인에 `--ioctl`/`--min-size`/`--max-size`/`--ioctl-random`을 전파.
   - `monitoring.py`에 `TARGET_IOCTLS`(리스트 모드) 및 `IOCTL_MODE=list|random` 설정을 도입하고, 과거의 `base_seed = 0x222004` 강제 고정 해킹 코드를 완전히 제거. IOCTL과 뮤테이션 시드가 로그·설정 양쪽에서 명확히 분리 표기되도록 수정.
2. **가변 페이로드 크기 도입:**
   - `WinKernel.Types.ixx`에 `MIN_PAYLOAD_SIZE(1)`/`MAX_PAYLOAD_SIZE(8192)` 상수 추가.
   - `WinKernel.Mutator.ixx`에 `MutatorEngine::NextSize()`를 추가. 커널 버퍼 임계값(2047/2048/2049 등) 부근을 집중 타격하는 경계값 목록과 균등 분포를 혼합해 결정론적(시드 기반)으로 매 반복 크기를 선택.
   - `WinKernel.Worker.ixx`가 고정 4096B 버퍼 생성을 폐기하고, 매 반복 `NextSize()`가 고른 크기로 페이로드를 새로 생성·변조하도록 변경. `FuzzReportPacket`의 `declaredSize/actualSize`에 실제 전송 크기를 실어 전송.
3. **실시간 로그 계측 보강:**
   - `monitoring.py`의 크래시/유죄 후보 announce 로그(`[SAVED:BSOD...]`, `[SAVED:SEH...]`, `[SAVED:BSOD-CAND]`, `[BSOD] Guilty candidate`) 4곳에 실제 사용된 단일 크기(`decl_size`)를 표기하도록 수정. 시작 로그의 범위 표기는 `size-range=`로 라벨을 명확히 구분.
4. **구조적 랜덤 IOCTL 모드(확장 기능) 추가:**
   - 완전 균일 32비트 랜덤은 device type 불일치로 대부분 `default` 분기(무크래시)로 낭비된다는 사실이 검증 과정에서 실증되었으므로, `WinKernel.Mutator.ixx::NextIoctl()`을 통해 "알려진 유효 코드 재사용(70%, exploitation) + CTL_CODE 구조를 지킨 인접 Function 탐색(30%, exploration)" 방식의 코퍼스 유도 랜덤을 `--ioctl-random`/`IOCTL_MODE=random` 옵션으로 추가. 기본값은 기존 결정론 리스트 모드로 유지하여 이미 검증된 재현 경로를 훼손하지 않음.

## 13. 검증 및 결과
동일 퍼저·동일 페이로드 생성기·동일 크기 범위(1~8192B)로 IOCTL만 다르게 하여 대조 실험을 수행했다.

| 조건 | 실행 결과 | 판정 |
|---|---|---|
| `TARGET_IOCTLS=0x222004` (HEVD 미정의) | InIoctl 6,999,999회 전부 완주, `rc=0` 정상 종료, **크래시 0건**(259초 소요) | 기대대로 무크래시 → 음성 케이스 통과 |
| `TARGET_IOCTLS=0x222003` (스택 오버플로우) | iter 1, size **8020B**에서 즉시 BSOD 재현 (`[SAVED:BSOD(kernel)] ... size 8020B iter 1`) | 임계(~2048B) 초과 시 결정론적 재현 → True Positive 확정 |

- 두 조건이 오직 IOCTL 유효성에 의해서만 갈렸으므로(페이로드 생성 로직·크기 범위 완전 동일), 크래시가 **퍼저/통신 코드의 논리적 결함(오탐)이 아니라 HEVD 드라이버 자체의 실제 취약점**임이 실증되었다.
- 실시간 로그에 크래시 케이스의 실제 크기가 단일 값(예: `size 8020B`)으로 표기됨을 확인하여 디버깅 계측 결함도 해소되었다.
- 빌드 검증: `_build_test/build.bat`로 전 모듈(`WinKernel.System/Types/IPC/Mutator/Engine/Logger/Driver/Process/Worker/Manager`, `main.cpp`) 컴파일 `BUILD_OK` 확인. `monitoring.py`는 `python -m py_compile`로 구문 검증 통과.
- 후속 조치: 워커 exe를 재빌드(Visual Studio Release 빌드)하여 로컬 및 VM 게스트(`C:\Fuzz`)에 재배포 완료, 실제 VM 환경에서 위 대조 실험 결과를 재현 확인함.
