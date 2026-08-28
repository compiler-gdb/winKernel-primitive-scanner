This project is for educational and vulnerability research purposes only. It is designed to help security researchers and developers understand kernel-level vulnerabilities and evaluate system stability. The author assumes no liability for any direct or indirect damage caused by the misuse of this software.

본 프로젝트는 교육 및 취약점 연구 목적으로만 제공됩니다. 보안 연구원과 개발자가 커널 드라이버의 취약점을 이해하고 시스템의 안정성을 평가하는 데 도움을 주기 위해 설계되었습니다. 본 소프트웨어의 오용 또는 이로 인해 발생하는 직간접적인 손해에 대해 저자는 어떠한 법적 책임도 지지 않습니다.

-----------
0.2.0 -> 0.3.0

**마스터-워커 멀티프로세싱 아키텍처 도입**

단일 프로세스에서 발생할 수 있는 크래시로 인해 퍼저 전체가 멈추는 문제를 해결하고, 병렬 테스팅을 가능하게 만들었습니다.

**마스터/워커 구조 분리:** wmain 진입점을 나누어, 인자 없이 실행하면 마스터 모드로, --worker <ID> 인자를 받으면 워커 모드로 분기하도록 설계.

**워커 프로세스 관리:** C++ 클래스로 Windows API(CreateProcessW, GetExitCodeProcess 등)를 캡슐화하여 자식 프로세스의 생성, 상태 조회, 강제 종료(Kill) 생명주기 관리.

**마스터 Watchdog 감시 로직:** 마스터가 워커의 상태를 1초마다 폴링(Polling)하며, 워커가 10초 이상 응답하지 않는 상태(Hang)일 경우 이를 감지하고 강제 종료하는 외부 방어 체계 구축.

**독립적인 세션 로깅:** 세션별 고유 디렉토리를 생성하고, 워커별로 독립된 파일(Process_N)에 기록을 남기는 FuzzLogger 연동.

---
0.3.0 -> 0.4.0

**비동기(Overlapped) I/O 및 워커 자체 회복(Self-Healing) 로직 적용**

동기식 커널 통신의 병목과 데드락 문제를 해결하여, 패킷 전송 속도를 극대화하고 워커의 생존력을 높인 버전입니다.

**논블로킹 통신 전환:** CreateFileW 호출 시 FILE_FLAG_OVERLAPPED 플래그를 적용하고, DeviceIoControl을 비동기 모드로 전환.

**워커 내부 미세 타임아웃 방어막:** 익명 이벤트 핸들(CreateEventW)과 WaitForSingleObject를 활용해 커널 응답을 최대 500ms까지만 대기하도록 워커 단의 미세 타임아웃 설정.

**스레드 구출 (CancelIo):** 500ms 내에 타깃 드라이버가 응답하지 않으면(Hang), CancelIo를 호출해 I/O 대기열에 갇힌 워커 스레드를 즉시 구출하고 프로세스 재생성 오버헤드 없이 다음 변조 데이터 전송.

**핸들 누수(Handle Leak) 해결:** 4,000만 번 타격 시 핸들이 1,400만 개 이상 누수되어 파이프라인 버퍼(96KB)에서 멈추던 치명적인 버그를 해결(CloseHandle(ov.hEvent) 누락 픽스).

---

0.4.0 -> 0.5.0

**무한 워커 재활용(Worker Recycling) 및 마스터 수퍼바이저(Supervisor) 고도화**

수천만 번의 IOCTL 타격으로 인한 커널 비페이지 풀(Non-Paged Pool) 고갈 및 파편화 한계를 돌파하여, 24시간 멈춤 없는 무한 퍼징 환경을 완성한 버전입니다.

**워커 재활용(Recycling) 전략 도입:** 워커 프로세스가 지정된 최대 타격 횟수(200만 회)에 도달하면 스스로 정상 종료(0 반환)하여, Windows OS가 해당 프로세스의 커널 IRP 잔재와 비페이지 풀 메모리를 강제 세척(Flush)하도록 유도.

**마스터 수퍼바이저 전환:** 마스터의 역할을 단순 대기(Batch)에서 상주형 수퍼바이저 데몬으로 개편하여, allFinished 루프를 제거하고 죽은 워커를 끊임없이 모니터링.

**자동 부활(Auto-Respawn) 시스템:** 워커가 종료되거나 크래시가 나면 그 즉시 동일한 ID를 가진 새 워커 프로세스로 교체. 부활 시 std::random_device를 통해 완벽히 새로운 난수 시드를 부여받아 중복 타격 방지.

**안전한 메모리 소유권 이전:** WorkerProcess 클래스에 C++11 우측값 참조(&&)를 이용한 이동 대입 연산자(operator=)를 구현. 객체 교체 과정에서 발생할 수 있는 기존 핸들 누수 방지 및 새로운 HANDLE의 소유권(Move Semantics) 안전 이전 확보.

---

0.5.0 -> 0.5.1

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

0.5.1 -> 0.5.2

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

0.5.2 -> 0.5.3

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
0.5.3 -> 0.5.4

**1) 안정성 및 크래시루프(CrashLoop) 방어 체계**

**드라이버 사전 검사 (Pre-Flight Check):** 마스터 프로세스 기동 즉시 타깃 드라이버 연결 가능 여부를 1회 검증하여, 드라이버 미로드 상태일 경우 워커 생성 없이 0초 만에 안전 종료(Abort).

**전역 프로세스 폭주 감시 (Global Crash Guard):** 워커가 비정상 조기 종료되어 무한 재생성(Fork Storm)되는 것을 방지하기 위해, 1초 윈도우 내 누적 10회 이상 조기 종료 감지 시 마스터가 모든 워커를 강제 종료하고 즉시 중단.

**폭주 카운터 오탐 수정:** 기존에는 Wait(0)이 참이 되는 즉시(정상 종료 포함) 무조건 카운터를 증가시켰음. exitCode != 0(비정상 종료)일 때만 카운트하도록 조건 추가.

<br><br>
**2) 행(Hang) 감시 로직 CPU 시간 기반으로 전면 교체**
**기존 문제:** 50ms 루프 × 600틱(30초) 고정 타임아웃 - 워커가 700만 회를 정상적으로 퍼징 중이어도 30초가 지나면 무조건 강제 종료(오탐 Kill).
**수정 후:** GetProcessTimes()로 워커의 커널+유저 CPU 누적 시간을 매 틱마다 비교. CPU 시간이 계속 증가 중이면(=실제로 일하는 중) 카운터를 리셋, 30초 동안 CPU 시간이 단 1ms도 움직이지 않을 때만 진짜 Hang으로 판정해 종료.
워커 재생성 시 lastCpuTimes 베이스라인을 0으로 초기화하여 새 워커가 이전 워커의 CPU 누적치로 인해 오탐되는 것을 방지.

<br><br>
**3) 프로세스 자원 관리 (WinKernel_Process.ixx)**

**핸들 누수 수정:** Close()에서 hThread_만 닫고 hProcess_는 닫지 않던 버그 수정 → CloseHandle(hProcess_) 추가.

**이동 대입 연산자 버그 수정:** 잘못된 센티널 값(INVALID_HANDLE_VALUE) 비교 로직을 제거하고 Close() 재사용으로 통일. 기존에 누락되어 있던 id_ 멤버 이전(transfer) 추가. 이동 후 원본 객체의 핸들을 nullptr + WorkerState::Idle로 통일해 이동 생성자와의 상태 불일치 제거.

**커맨드라인 버퍼 오버플로우 방지:** Launch()에서 고정 크기 스택 버퍼(wchar_t[MAX_PATH], 260자) 대신 std::wstring 가변 버퍼 사용. 기존에는 커맨드라인이 260자를 넘기면 wcscpy_s가 프로세스를 강제 Abort시켰음.

**Hang 감지용 접근자 추가:** Manager의 CPU 시간 기반 Hang 판정이 가능하도록 GetProcessHandle() 게터 추가.

**4) 정수 언더플로우 방지 (WinKernel_Manager.ixx)**
WorkerManager() 기본 생성자와 MasterController::Run()의 코어 수 계산에서, hardware_concurrency() / GetLogicalCoreCount()가 2 이하를 반환할 경우 DWORD(unsigned) 뺄셈으로 인한 언더플로우(거대한 양수 발생 → 워커 수 폭주)를 삼항 연산자로 원천 차단.

---

0.5.4 -> 0.6.0
파일 기반 IPC를 통째로 폐기, TCP + VM 스냅샷 리셋 루프로 재설계

**1) VM 스냅샷 자동 복구 루프 (monitoring.py 신규)**

**크래시 발생 시 자동 되돌리기:** 매 라운드마다 revertToSnapshot으로 VM을 클린 상태로 되돌린 뒤 전원을 켜고, VMware Tools 초기화를 대기(wait_for_tools)한 다음 퍼저 워커 exe를 게스트에 재주입(stage_worker_to_local)하고 실행.

**BSOD 판정:** 게스트에 VMware Tools가 응답하는지(guest_tools_alive)로 크래시 여부를 판단. 초기 정착 시간(initial_settle) + 유예 시간(grace_seconds) 동안 연속 정상 응답(healthy_streak)이 없으면 다운(BSOD)으로 확정(confirm_guest_down).

**무한 루프화:** 크래시 발생 → 유죄 시드 저장 → 리버트 → 재실행을 Ctrl+C 전까지 반복.

<br><br>
**2) 파일/HGFS 기반 IPC 전면 폐기 → TCP 소켓 리포팅**

**온-와이어 프로토콜 신설 (WinKernel_IPC.ixx):** FuzzReportPacket(304바이트 고정 POD, #pragma pack(1))을 정의해 워커→호스트 단방향 스트리밍. Python 쪽은 struct.Struct("<8IQ2I256s")로 1:1 언패킹.

**TcpReporter 클라이언트 추가:** 워커가 시작 시 호스트(monitoring.py)에 접속하고, DeviceIoControl 호출 직전마다 현재 시드/IOCTL/페이로드 스냅샷을 전송. TCP_NODELAY로 Nagle 지연을 제거해 BSOD 직전 마지막 패킷이 커널 버퍼에 갇히지 않도록 함.

**유죄 시드 귀속 원리 변경:** 기존엔 공유 메모리/HGFS에 상태를 기록해 뒤늦게 pull 했지만, 이제는 소켓이 끊기는 순간(BSOD) 호스트가 이미 들고 있던 "마지막 InIoctl 패킷"이 곧 유죄 후보가 됨 (디스크 경유 없음 → revert 시 소실 위험 제거).
리포트 채널 미연결 시 안전 종료: 호스트와 연결 안 되면 DeviceIoControl을 아예 쏘지 않고 워커를 종료 → 귀속 불가능한 크래시 방지.

<br><br>
**3) 호스트 주도 결정론적 시드/커서 시스템**

fuzz_cursor.txt에 base_seed/start_ioctl을 영속화하여, VM을 리버트해도 이전 라운드 진행 지점부터 재현 가능하게 함.

워커별 시드는 base_seed + workerId로 충돌 없이 분배, 커맨드라인에 0xSEED <startIoctl> --report-host <h> --report-port <p>로 전달.

main.cpp에 --base-seed, --start-ioctl, --report-host, --report-port 인자 파싱 추가 (마스터/워커 공통).

<br><br>
**4) 유저모드 SEH 자가 회복 (WinKernel_Worker.ixx)**

SendIoctlGuarded() 함수로 DeviceIoControl 호출을 __try/__except로 감싸, 커널이 반환한 OS 레벨 예외(0xC0000005 등)를 프로세스 크래시 없이 흡수하고 다음 반복으로 자가 복귀.

동일 (IOCTL, Seed) 조합은 워커 생애당 1회만 Crashed 리포트 → 호스트 측 중복 덤프 방지.

흡수된 예외 로그는 첫 발생 + 1000회 단위로만 기록해 핫패스 로그 폭주 방지.

<br><br>
**5) 마스터 감시 루프 재설계 (WinKernel_Manager.ixx)**

**자폭(Fork Storm Abort) 트리거 폐기:** 동시 다발적 워커 종료는 인프라 오류가 아니라 "드라이버 전멸(BSOD 진행 중)" 신호일 수 있으므로, 마스터가 스스로 종료하지 않고 경고 로그만 남긴 뒤 계속 재기동.

**Mass Hang(전역 정지) 판정 추가:** 과반 워커가 동시에 CPU 진척 없이 멈추면 개별 Hang이 아니라 커널 전체가 죽어가는 중(지연 BSOD, 0x1E)으로 간주해 어떤 워커도 강제 종료하지 않고 무한 대기.

**개별 Hang 강제 종료 로직 제거:** 기존 30초 CPU 무진척 시 즉시 Kill하던 로직을 삭제하고, 대신 ~20분 무진척 시 진단 로그 1회만 남기고 방치(지연 BSOD 완성을 위해 워커를 살려둠).

<br><br>
**6) 드라이버 사전 검사 진단 강화**

DriverController::LastError() 추가로 CreateFileW 실패 원인(ERROR_FILE_NOT_FOUND=미로드, ERROR_ACCESS_DENIED=권한부족)을 구분.
IsProcessElevated()로 현재 프로세스의 관리자 권한 여부를 함께 진단 로그에 출력.
 
<br><br>
**7) 페이로드 크기 고정**

가변 크기 이스케일레이션 로직을 제거하고, 모든 IOCTL 페이로드를 DEFAULT_BUFFER_SIZE(4096, PAGE_SIZE)로 고정 — 해당 크기에서 취약점이 직격 재현됨을 확인.

<br><br>
**8) 기타 안정성 보강**

wmain 전체를 try/catch로 감싸 예외 발생 시 크래시 대신 코드 99/98로 안전 종료.

로케일 설정(std::locale::global)을 try/catch로 래핑해 POSIX 로케일 문자열 오류로 인한 즉시 크래시 방지.

WinKernel_Types.ixx에 센티널 정책 기반 RAII 핸들 래퍼(UniqueHandle, MappedView) 및 CrashClass(Benign/Crash/Hang) enum 추가 — 향후 핸들 누수 차단 및 크래시 분류 확장 대비.

monitoring.py에 TCP 리포트 포트용 방화벽 인바운드 규칙 자동 등록(ensure_firewall_inbound) 추가.

---

0.6.0 -> 0.6.1

**1) 인프라 결함 제어 및 컨트롤러 생존성 강화**

**vmrun 호출 타임아웃 및 재시도 메커니즘 도입:** 스냅샷 락(Lock)이나 VM 지연 발생 시 컨트롤러가 무한 블로킹되는 현상을 방지하기 위해 VM_OP_TIMEOUT(180초)을 적용하고, 지수 백오프 기반 재시도 로직(VM_MAX_RETRIES=3)을 구축하여 컨트롤러 프로세스 자폭 방지.

**라운드 예외 격리:** 무인 퍼징 루프 내 예기치 못한 서브 프로세스/네트워크/IO 예외 발생 시, 컨트롤러 전체가 종료되지 않도록 흡수하고 다음 라운드로 안전하게 이행하는 내결함성 확보.

<br>

**2) BSOD 레이스 완화 및 커널 대기 안정성 확보**

**다중 워커 BSOD 공동 후보(Candidate) 보존:** 커널 패닉 직전 단일 1개 패킷만 수거하여 발생하던 유죄 시드 오귀속 레이스를 극복하기 위해, 프리즈 2초 전까지 통신했던 워커들의 시드를 공동 후보 스냅샷으로 원천 영속화.

**지연 BSOD 보존을 위한 워커 자폭/사살 경로 제거:** 무진척/데드락 워커를 성급히 강제 종료(Kill)할 경우 지연성 커널 예외(0x1E BSOD) 작성이 중단되는 문제를 방지하고자, 프로세스 사살 로직을 제거하고 커널이 스스로 뻗을 때까지 방치 대기하도록 전환.

<br>

**3) 보안 강화 및 네트워크 안정성 확보**

**자격 증명 분리 및 환경 변수화:** VMX 경로 및 게스트/vmrun 비밀번호 등의 하드코딩 요소를 제거하고 fuzzer.env 기반 구성 파싱 및 검증 단계(validate_config)를 도입하여 커밋 위험 차단.

**TCP 소스 IP 필터링 및 송신 타임아웃 적용:** 허용된 VMnet 대역 외 실체 없는 접속을 차단하는 1차 방어선을 구축하고, C++ 워커 송신 측에 SO_SNDTIMEO(5s)를 적용하여 네트워크 지연 시 워커 스레드 블로킹 예방. 
