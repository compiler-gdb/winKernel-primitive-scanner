This project is for educational and vulnerability research purposes only. It is designed to help security researchers and developers understand kernel-level vulnerabilities and evaluate system stability. The author assumes no liability for any direct or indirect damage caused by the misuse of this software.

본 프로젝트는 교육 및 취약점 연구 목적으로만 제공됩니다. 보안 연구원과 개발자가 커널 드라이버의 취약점을 이해하고 시스템의 안정성을 평가하는 데 도움을 주기 위해 설계되었습니다. 본 소프트웨어의 오용 또는 이로 인해 발생하는 직간접적인 손해에 대해 저자는 어떠한 법적 책임도 지지 않습니다.

-----------
0.2.0 -> v0.3.0

**마스터-워커 멀티프로세싱(Multi-Processing) 아키텍처 도입**

단일 프로세스에서 발생할 수 있는 크래시로 인해 퍼저 전체가 멈추는 문제를 해결하고, 병렬 테스팅을 가능하게 만들었습니다.

마스터/워커 구조 분리: wmain 진입점을 나누어, 인자 없이 실행하면 마스터 모드로, --worker <ID> 인자를 받으면 워커 모드로 분기하도록 설계.

워커 프로세스 관리 (WorkerProcess): C++ 클래스로 Windows API(CreateProcessW, GetExitCodeProcess 등)를 캡슐화하여 자식 프로세스의 생성, 상태 조회, 강제 종료(Kill) 생명주기 관리.

마스터 Watchdog 감시 로직: 마스터가 워커의 상태를 1초마다 폴링(Polling)하며, 워커가 10초 이상 응답하지 않는 상태(Hang)일 경우 이를 감지하고 강제 종료하는 외부 방어 체계 구축.

독립적인 세션 로깅: 세션별 고유 디렉토리를 생성하고, 워커별로 독립된 파일(Process_N)에 기록을 남기는 FuzzLogger 연동.

---
0.3.0 -> v0.4.0

**비동기(Overlapped) I/O 및 워커 자체 회복(Self-Healing) 로직 적용**

동기식 커널 통신의 병목과 데드락 문제를 해결하여, 패킷 전송 속도를 극대화하고 워커의 생존력을 높인 버전입니다.

논블로킹(Non-Blocking) 통신 전환: CreateFileW 호출 시 FILE_FLAG_OVERLAPPED 플래그를 적용하고, DeviceIoControl을 비동기 모드로 전환.

워커 내부 미세 타임아웃 방어막: 익명 이벤트 핸들(CreateEventW)과 WaitForSingleObject를 활용해 커널 응답을 최대 500ms까지만 대기하도록 워커 단의 미세 타임아웃 설정.

스레드 구출 (CancelIo): 500ms 내에 타깃 드라이버가 응답하지 않으면(Hang), CancelIo를 호출해 I/O 대기열에 갇힌 워커 스레드를 즉시 구출하고 프로세스 재생성 오버헤드 없이 다음 변조 데이터 전송.

핸들 누수(Handle Leak) 해결: 4,000만 번 타격 시 핸들이 1,400만 개 이상 누수되어 파이프라인 버퍼(96KB)에서 멈추던 치명적인 버그를 해결(CloseHandle(ov.hEvent) 누락 픽스).

---

0.4.0 -> v0.5.0

**무한 워커 재활용(Worker Recycling) 및 마스터 수퍼바이저(Supervisor) 고도화**

수천만 번의 IOCTL 타격으로 인한 커널 비페이지 풀(Non-Paged Pool) 고갈 및 파편화 한계를 돌파하여, 24시간 멈춤 없는 무한 퍼징 환경을 완성한 버전입니다.

워커 재활용(Recycling) 전략 도입: 워커 프로세스가 지정된 최대 타격 횟수(200만 회)에 도달하면 스스로 정상 종료(0 반환)하여, Windows OS가 해당 프로세스의 커널 IRP 잔재와 비페이지 풀 메모리를 강제 세척(Flush)하도록 유도.

마스터 수퍼바이저(Supervisor) 전환: 마스터의 역할을 단순 대기(Batch)에서 상주형 수퍼바이저 데몬으로 개편하여, allFinished 루프를 제거하고 죽은 워커를 끊임없이 모니터링.

자동 부활(Auto-Respawn) 시스템: 워커가 종료되거나 크래시가 나면 그 즉시 동일한 ID를 가진 새 워커 프로세스로 교체. 부활 시 std::random_device를 통해 완벽히 새로운 난수 시드를 부여받아 중복 타격 방지.

안전한 메모리 소유권 이전: WorkerProcess 클래스에 C++11 우측값 참조(&&)를 이용한 이동 대입 연산자(operator=)를 구현. 객체 교체 과정에서 발생할 수 있는 기존 핸들 누수 방지 및 새로운 HANDLE의 소유권(Move Semantics) 안전 이전 확보.

---

0.5.0 -> v0.5.1

**멀티코어 CPU 자원 할당 정책 최적화 및 퍼징 처리량(Throughput) 극대화**
마스터 프로세스의 워커 할당 공식을 개선하여, 고사양 가상머신(VM) 및 멀티코어 환경에서 시스템 안정성을 해치지 않으면서 퍼징 화력을 최대치로 끌어올린 패치 버전입니다.

워커 할당 정책 최적화 (core / 2  에서 core - 2로 수정)

기존의 전체 코어 50%만 사용하던 보수적인 분할 방식을 개편하여, OS 및 마스터 프로세스용 여유 코어(1~2개)만 남겨두고 가용 CPU 자원을 최대로 활용하도록 공식 수정.

동시 퍼징 처리량(Throughput) 대폭 향상:

16코어 가상머신 기준 활성 워커 프로세스가 8개에서 14개로 증가하여, 전체 퍼징 패킷 전송 화력 및 커버리지 탐색 속도 약 75% 상승.

마스터 기아(Starvation) 및 커널 DPC 지연 방지:

모든 코어(16개)를 꽉 채우지 않고 2개 코어를 전용으로 보존하여, 마스터 프로세스의 감시(Watchdog) 폴링 주기 밀림으로 인한 워커 오탐방지 및 커널 인터럽트/DPC 처리 지연 현상 원천 차단.
