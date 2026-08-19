This project is for educational and vulnerability research purposes only. It is designed to help security researchers and developers understand kernel-level vulnerabilities and evaluate system stability. The author assumes no liability for any direct or indirect damage caused by the misuse of this software.

본 프로젝트는 교육 및 취약점 연구 목적으로만 제공됩니다. 보안 연구원과 개발자가 커널 드라이버의 취약점을 이해하고 시스템의 안정성을 평가하는 데 도움을 주기 위해 설계되었습니다. 본 소프트웨어의 오용 또는 이로 인해 발생하는 직간접적인 손해에 대해 저자는 어떠한 법적 책임도 지지 않습니다.

---
## WinKernel Primitive Scanner

### Overview

Windows 커널 드라이버의 취약점 및 통신 원시 패턴(Primitives)을 병렬로 진단하는 멀티프로세스 기반 스캐너입니다. Master Supervisor가 다중 Worker Process의 생명주기를 감시하며, 예외 발생 시 자가 복구 및 드라이버 I/O 안정성을 유지합니다.

---
### 0.2.0 -> 0.3.0

**마스터-워커 멀티프로세싱 아키텍처 도입**

단일 프로세스에서 발생할 수 있는 크래시로 인해 퍼저 전체가 멈추는 문제를 해결하고, 병렬 테스팅을 가능하게 만들었습니다.

**마스터/워커 구조 분리:** wmain 진입점을 나누어, 인자 없이 실행하면 마스터 모드로, --worker <ID> 인자를 받으면 워커 모드로 분기하도록 설계.

**워커 프로세스 관리:** C++ 클래스로 Windows API(CreateProcessW, GetExitCodeProcess 등)를 캡슐화하여 자식 프로세스의 생성, 상태 조회, 강제 종료(Kill) 생명주기 관리.

**마스터 Watchdog 감시 로직:** 마스터가 워커의 상태를 1초마다 폴링(Polling)하며, 워커가 10초 이상 응답하지 않는 상태(Hang)일 경우 이를 감지하고 강제 종료하는 외부 방어 체계 구축.

**독립적인 세션 로깅:** 세션별 고유 디렉토리를 생성하고, 워커별로 독립된 파일(Process_N)에 기록을 남기는 FuzzLogger 연동.

---
### 0.3.0 -> 0.4.0

**비동기(Overlapped) I/O 및 워커 자체 회복(Self-Healing) 로직 적용**

동기식 커널 통신의 병목과 데드락 문제를 해결하여, 패킷 전송 속도를 극대화하고 워커의 생존력을 높인 버전입니다.

**논블로킹 통신 전환:** CreateFileW 호출 시 FILE_FLAG_OVERLAPPED 플래그를 적용하고, DeviceIoControl을 비동기 모드로 전환.

**워커 내부 미세 타임아웃 방어막:** 익명 이벤트 핸들(CreateEventW)과 WaitForSingleObject를 활용해 커널 응답을 최대 500ms까지만 대기하도록 워커 단의 미세 타임아웃 설정.

**스레드 구출 (CancelIo):** 500ms 내에 타깃 드라이버가 응답하지 않으면(Hang), CancelIo를 호출해 I/O 대기열에 갇힌 워커 스레드를 즉시 구출하고 프로세스 재생성 오버헤드 없이 다음 변조 데이터 전송.

**핸들 누수(Handle Leak) 해결:** 4,000만 번 타격 시 핸들이 1,400만 개 이상 누수되어 파이프라인 버퍼(96KB)에서 멈추던 치명적인 버그를 해결(CloseHandle(ov.hEvent) 누락 픽스).

---

### 0.4.0 -> 0.5.0

**무한 워커 재활용(Worker Recycling) 및 마스터 수퍼바이저(Supervisor) 고도화**

수천만 번의 IOCTL 타격으로 인한 커널 비페이지 풀(Non-Paged Pool) 고갈 및 파편화 한계를 돌파하여, 24시간 멈춤 없는 무한 퍼징 환경을 완성한 버전입니다.

**워커 재활용(Recycling) 전략 도입:** 워커 프로세스가 지정된 최대 타격 횟수(200만 회)에 도달하면 스스로 정상 종료(0 반환)하여, Windows OS가 해당 프로세스의 커널 IRP 잔재와 비페이지 풀 메모리를 강제 세척(Flush)하도록 유도.

**마스터 수퍼바이저 전환:** 마스터의 역할을 단순 대기(Batch)에서 상주형 수퍼바이저 데몬으로 개편하여, allFinished 루프를 제거하고 죽은 워커를 끊임없이 모니터링.

**자동 부활(Auto-Respawn) 시스템:** 워커가 종료되거나 크래시가 나면 그 즉시 동일한 ID를 가진 새 워커 프로세스로 교체. 부활 시 std::random_device를 통해 완벽히 새로운 난수 시드를 부여받아 중복 타격 방지.

**안전한 메모리 소유권 이전:** WorkerProcess 클래스에 C++11 우측값 참조(&&)를 이용한 이동 대입 연산자(operator=)를 구현. 객체 교체 과정에서 발생할 수 있는 기존 핸들 누수 방지 및 새로운 HANDLE의 소유권(Move Semantics) 안전 이전 확보.

---

### 0.5.0 -> 0.5.1

**1. 멀티코어 CPU 자원 할당 정책 최적화 및 퍼징 처리량 극대화**
마스터 프로세스의 워커 할당 공식을 개선하여, 고사양 가상머신(VM) 및 멀티코어 환경에서 시스템 안정성을 해치지 않으면서 퍼징 화력을 최대치로 끌어올린 패치 버전입니다.

워커 할당 정책 최적화 (core / 2  에서 core - 2로 수정)

기존의 전체 코어 50%만 사용하던 보수적인 분할 방식을 개편하여, OS 및 마스터 프로세스용 여유 코어(1~2개)만 남겨두고 가용 CPU 자원을 최대로 활용하도록 공식 수정.
<br><br>
**2. 동시 퍼징 처리량 대폭 향상:**

16코어 가상머신 기준 활성 워커 프로세스가 8개에서 14개로 증가하여, 전체 퍼징 패킷 전송 화력 및 커버리지 탐색 속도 약 75% 상승.
<br><br>
**3. 마스터 기아(Starvation) 및 커널 DPC 지연 방지:**

모든 코어(16개)를 꽉 채우지 않고 2개 코어를 전용으로 보존하여, 마스터 프로세스의 감시(Watchdog) 폴링 주기 밀림으로 인한 워커 오탐방지 및 커널 인터럽트/DPC 처리 지연 현상 원천 차단.

---

### 0.5.1 -> 0.5.2

**1. 마스터 프로세스 감시 루프 논블로킹 전환 (Wait(0))**

**동기식 1초 대기 제거:** 기존 worker.Wait(1000)으로 인해 마스터 스레드가 멈추며 워커들이 1초 단위 그룹(0~3, 4~9 등)으로 묶여 부활하던 위상 고정(Phase Lock) 병목 완벽 해결.

**즉각적인 상태 조회 및 개별 부활:** worker.Wait(0)을 적용하여 200만 번을 마친 워커가 발생하는 즉시 마이크로초 단위로 감지하고 1:1로 즉시 교체(Respawn).

**CPU 점유율 제어 및 Hang 오탐 방지:** 루프 말미에 Sleep(50)(50ms)을 배치하여 마스터 CPU 점유율을 0~1%로 억제하고, 루프 주기에 맞춰 Hang 판정 카운터를 보정하여 정상 실행 중인 워커의 강제 처단 방지.

<br><br>

**2. 고성능 로깅 및 라이프사이클 텔레메트리 구축**
    
**중간 카운터 로그 제거 (Zero Disk I/O):** 100만 번마다 남기던 단순 진행 로그를 제거하여 고속 루프 구간에서의 파일 쓰기 오버헤드 원천 차단.

**프로세스 라이프사이클 구분선 추가:** 워커가 새로 뜰 때마다 Process_N.txt에 명확한 구분선과 함께 PID, 시작 난수 시드(Seed), 타깃 IOCTL 정보를 기록하여 수명 주기별 격리 가독성 확보.

**세션 완료 요약(SUMMARY) 통계 도입:** 워커가 200만 번을 채우고 재활용될 때 총 소요 시간 및 초당 처리 속도(execs/sec)를 1줄로 요약 기록하여 퍼징 화력 측정 가능.

**크래시/에러 진단 정보 고도화:** IOCTL 실패 시 Win32 에러 코드(GetLastError())를 10진수/16진수로 함께 기록하여 드라이버 거부 원인 판별 지원.

---

### 0.5.2 -> 0.5.3

**1) 아키텍처 모듈화 및 단일 책임 원칙(SRP) 확립**
**`main.cpp` 경량화 (CLI 라우터화):** main.cpp에 집중되어 있던 마스터/워커 실행 루프와 설정을 분리하여, 명령행 인자(`--worker`)에 따라 분기하는 순수 진입점(Entry Point, ~20줄)으로 축소.

**신규 모듈 WinKernel.Worker.ixx 분리:**: 워커 프로세스의 IOCTL 전송 루프, 변이 엔진 연동, 라이프사이클 로깅을 독립 모듈로 캡슐화.
  
**`WinKernel.Manager.ixx` 마스터 관제탑(`MasterController`) 캡슐화:** 마스터 프로세스의 워커 스폰, 논블로킹 감시, 행(Hang) 처리 및 폭주 방어 로직을 클래스 내부로 캡슐화.

**공통 상수 전역 이관 (`WinKernel.Types.ixx`):** 타깃 드라이버 명칭, IOCTL 코드, 최대 반복 횟수 등의 설정을 `WinKernel::Constants` 네임스페이스로 통합 관리.

<br><br>
**2) 안정성 및 크래시루프(CrashLoop) 방어 체계**

**드라이버 사전 검사 (Pre-Flight Check):** 마스터 프로세스 기동 즉시 타깃 드라이버 연결 가능 여부를 1회 검증하여, 드라이버 미로드 상태일 경우 워커 생성 없이 0초 만에 안전 종료(Abort).

**전역 프로세스 폭주 감시 (Global Crash Guard):** 워커 프로세스들이 비정상 조기 종료되어 무한 재생성(Fork Storm)되는 것을 방지하기 위해, 1초 윈도우 내 누적 10회 이상 조기 종료 감지 시 마스터가 모든 자원을 회수하고 즉시 중단.

**행(Hang) 감시 타이머 보정:** 50ms 루프 주기 기준 600틱($50\text{ms} \times 600 = 30,000\text{ms} = 30\text{초}$) 타임아웃 주석 및 로직 정비.

<br><br>
**3) 퍼징 파이프라인 및 페이로드 튜닝**

**기본 페이로드 버퍼 확장 (4096 바이트):** HEVD(x64) 스택 버퍼 크기($0x800$, 2048 바이트)를 안정적으로 초과하여 커널 패닉(BSOD / BugCheck)을 유발할 수 있도록 `DEFAULT_BUFFER_SIZE`를 4096 바이트로 상향.

**워커 수명 주기 최적화 (700만 회):** 프로세스 재생성 오버헤드를 줄이고 장기 가동률을 극대화하기 위해 워커 리사이클 주기를 7,000,000회로 확장.

---

### 0.5.3 -> 0.5.4

**Fault-Tolerant Driver Pipeline:**
비동기 I/O 타임아웃 발생 시 `CancelIo` 직후 `GetOverlappedResult`를 동기 대기(Drain)하여 IRP 잔류 및 스택 메모리 오염 원천 방지.

**Adaptive CPU Time Hang Detection:**
30초 단순 고정 타이머 대신 `GetProcessTimes` API를 활용하여 워커의 실제 CPU 진척도를 추적, 무한 루프/데드락 발생 시 정밀 감지 및 재활용(Recycle).

**CrashLoop Spawn Storm Guard:**
정상 종료(`exitCode == 0`)가 아닌 비정상 크래시 루프 상황에서만 폭주 카운터가 증가하도록 방어 로직 격리.

**Robust Resource Lifecycle:**
핸들 센티널을 `nullptr`로 일원화하고 `CloseHandle` 누수를 차단하여 대규모 장기 스캔 시 안정성 확보.
가용 코어 연산 시 부호 없는 정수(unsigned) 언더플로우 방어 가드 적용.

---

## Architecture

**`WinKernel.Driver.ixx`**: 비동기 Overlapped IOCTL 통신 및 IRP 라이프사이클 관리

**`WinKernel.Process.ixx`**: 개별 Worker 프로세스 생성, 상태 추적 및 핸들 캡슐화

**`WinKernel.Manager.ixx`**: 코어 수 기반 병렬 워커 풀 관리, CPU 진척도 모니터링, 폭주 방어

**`WinKernel.Types.ixx`**: 공용 상태 머신(WorkerState) 및 공유 구조체 정의
