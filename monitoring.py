import os
import socket
import struct
import subprocess
import threading
import time
import random
import hashlib
import ipaddress
import sys
from datetime import datetime

#  WinKernel Fuzzer Controller  (TCP Socket IPC 재설계)

# ================= 설정 로딩 (P5: 자격 증명 분리) =================
# [Fix: P5] 비밀번호 등 자격 증명과 배포 환경별 경로를 소스에 평문 하드코딩하지 않는다.
#   - 우선순위: fuzzer.env 파일 > 프로세스 환경변수 > 코드 내 기본값.
#   - fuzzer.env 는 .gitignore 로 추적 제외한다. 템플릿은 fuzzer.env.example 참고.
#   - 필수값(비밀번호/경로)이 없으면 main() 시작 시 validate_config()가 친절한 안내 후 종료한다.
ENV_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fuzzer.env")
ENV_EXAMPLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fuzzer.env.example")


def load_env_file(path):
    # KEY=VALUE 형식의 최소 파서(외부 의존성 없이 stdlib만 사용). '#' 주석/빈 줄 무시, 값 양끝 따옴표 제거.
    data = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k:
                    data[k] = v
    except OSError:
        pass  # 파일 부재는 정상 흐름(환경변수/기본값으로 대체, 필수값 누락은 validate_config가 판정)
    return data


_CFG = load_env_file(ENV_FILE_PATH)


def cfg(key, default=""):
    # 설정값 조회: fuzzer.env > os.environ > default 순으로 해석.
    v = _CFG.get(key)
    if v is None:
        v = os.environ.get(key)
    return v if v is not None else default


# ================= VM / vmrun Config =================
VMRUN_PATH = cfg("VMRUN_PATH", r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe")
VMX_PATH = cfg("VMX_PATH")                 # [필수] .vmx 경로
SNAPSHOT_NAME = cfg("SNAPSHOT_NAME", "set_host2")
VM_USER = cfg("VM_USER", "Administrator")
VM_PASS = cfg("VM_PASS")                   # [필수/비밀] 게스트 로그인 비밀번호
VM_ACCESS_PASS = cfg("VM_ACCESS_PASS")     # [필수/비밀] vmrun 접근 비밀번호

# [Fix: 내장 Administrator 계정 권장 안내]
# 만약 여전히 rc=1이 발생한다면 VM 내 계정을 내장 'Administrator'로 변경하거나 
# VM_USER = "Administrator" 로 수정하여 UAC 토큰 필터링을 우회하세요.

# 호스트 로컬 exe 경로 및 게스트 스테이징 경로
HOST_WORKER_EXE = cfg("HOST_WORKER_EXE")   # [필수] 호스트의 워커 exe 경로(게스트로 주입할 원본)
GUEST_LOCAL_DIR = cfg("GUEST_LOCAL_DIR", r"C:\Fuzz")
# [Fix: P5] 게스트 내 스테이징 exe 경로. 미지정 시 게스트 디렉터리 + 호스트 exe 파일명으로 자동 구성.
_default_guest_exe = os.path.join(GUEST_LOCAL_DIR, os.path.basename(HOST_WORKER_EXE)) if HOST_WORKER_EXE else ""
GUEST_LOCAL_EXE = cfg("GUEST_LOCAL_EXE", _default_guest_exe)

HANG_TIMEOUT = 300
BSOD_GRACE_SECONDS = 180
BSOD_GRACE_POLL = 5
BSOD_INITIAL_SETTLE = 10

# [Fix: P1] BSOD 유죄 귀속 레이스 완화: 단일 "전역 마지막 InIoctl"만이 아니라,
#   프리즈 직전 InIoctl 중이던 워커들을 공동 후보로 함께 보존하기 위한 설정.
#   - BSOD_CANDIDATE_WINDOW_MS: 최신 InIoctl 타임스탬프 대비 이 시간(ms) 이내에 InIoctl 중이던
#     워커만 공동 후보로 포함(게스트 프리즈로 모든 워커가 거의 동시에 멈춘 시점 근처를 포착).
#   - BSOD_CANDIDATE_MAX: 후보 파일 개수 상한(과다 저장 방지).
BSOD_CANDIDATE_WINDOW_MS = 2000
BSOD_CANDIDATE_MAX = 8

# [Fix: P0] vmrun 호출 실패로 컨트롤러 프로세스 자체가 죽지 않도록 재시도/백오프/타임아웃 상한 도입.
#   - VM_OP_TIMEOUT: revert/start 같은 개별 vmrun 호출의 최대 대기(초). 스냅샷 락으로 인한 무한 블로킹 차단.
#   - VM_MAX_RETRIES: 라운드 준비(revert+start) 실패 시 재시도 횟수 상한. 무한 재시도 루프 방지.
#   - VM_RETRY_BACKOFF: 재시도 간 지수 백오프 기준(초). 15 -> 30 -> 60 ... 으로 증가.
VM_OP_TIMEOUT = 180
VM_MAX_RETRIES = 3
VM_RETRY_BACKOFF = 15

# ================= 크래시 시드 영속(호스트 로컬) =================
HOST_SHARED_DIR = cfg("HOST_SHARED_DIR")   # [필수] 크래시/시드 저장 디렉터리
# [Fix: P5] HOST_SHARED_DIR 미설정 시에도 import가 깨지지 않도록 상대경로로 폴백(실제 실행은 validate_config가 차단).
CRASH_DIR = os.path.join(HOST_SHARED_DIR, "crashes") if HOST_SHARED_DIR else "crashes"
PENDING_SEED_PATH = os.path.join(HOST_SHARED_DIR, "pending_seed.bin") if HOST_SHARED_DIR else "pending_seed.bin"

# ================= TCP IPC Config =================
LISTEN_HOST = "0.0.0.0"   
LISTEN_PORT = 51337       
HOST_IP_FOR_GUEST = cfg("HOST_IP_FOR_GUEST", "")  # 비우면 자동 감지. 예: "192.168.175.1"

REPORT_STRUCT = struct.Struct("<8IQ2I256s")
RECORD_SIZE = REPORT_STRUCT.size  
REPORT_MAGIC = b"KTCP"            
PHASE_INIT, PHASE_PREIOCTL, PHASE_INIOCTL, PHASE_POSTIOCTL, PHASE_COMPLETED, PHASE_CRASHED = range(6)
PHASE_NAMES = {0: "Init", 1: "PreIoctl", 2: "InIoctl", 3: "PostIoctl", 4: "Completed", 5: "Crashed"}

SOCKET_IDLE_TIMEOUT = 30  

# ================= TCP IPC 소스 제한 (P3) =================
# [Fix: P3] 리포트 채널은 매직 넘버(KTCP)만 검사하므로 소스 위조에 취약하다. 격리 랩(호스트<->게스트 vmnet)
#   전제하에 과도한 인증 없이 (1) vmnet 인터페이스 바인드 + (2) 게스트 소스 IP 필터로 실용적으로 제한한다.
BIND_TO_HOST_IP = True        # True면 0.0.0.0 대신 게스트가 접속하는 host_ip 인터페이스에만 바인드(실패 시 0.0.0.0 폴백)
# 허용 게스트 소스 IP 목록. 비우면 host_ip의 /24(vmnet 서브넷)를 자동 허용. 특정 게스트만 원하면 IP를 명시.
ALLOWED_GUEST_IPS = []        # 예: ["192.168.175.128"]

# ================= 호스트 주도 결정론 커서 =================
CURSOR_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fuzz_cursor.txt")
SEED_STRIDE = 256
SEED_MASK = 0xFFFFFFFF
# =========================================================

# ================= 타깃 IOCTL / 가변 크기 설정 =================
# [수정] IOCTL 코드는 이제 base_seed(뮤테이션 시드)와 완전히 분리된 별도 설정이다.
#   - TARGET_IOCTLS: 쉼표/공백 구분 목록. 예) "0x222003" 또는 "0x222003,0x222007".
#     음성(negative) 케이스 검증 시 "0x222004"처럼 HEVD 미정의 코드를 넣어 "크래시 없음"을 관측한다.
#   - FUZZ_MIN_SIZE/FUZZ_MAX_SIZE: 워커가 매 반복 페이로드 크기를 이 범위에서 가변 선택(크기 고정 착시 제거).
def _parse_ioctls(s):
    out = []
    for tok in str(s).replace(",", " ").split():
        try:
            out.append(int(tok, 0) & 0xFFFFFFFF)
        except ValueError:
            pass
    return out or [0x222003]

TARGET_IOCTLS = _parse_ioctls(cfg("TARGET_IOCTLS", "0x222003"))
# [수정] IOCTL 선택 모드. 기본 "list"(검증용 결정론 리스트) / "random"(코퍼스 기반 구조적 랜덤, opt-in).
#   random 모드는 워커가 시드로 IOCTL 시퀀스를 재현 가능하게 생성하므로, TARGET_IOCTLS(list)는 그대로 두어도
#   검증 재현성이 유지된다(모드만 바꿔 켬).
IOCTL_MODE = str(cfg("IOCTL_MODE", "list")).strip().lower()
IOCTL_RANDOM = (IOCTL_MODE == "random")
try:
    FUZZ_MIN_SIZE = int(cfg("FUZZ_MIN_SIZE", "1"), 0)
except ValueError:
    FUZZ_MIN_SIZE = 1
try:
    FUZZ_MAX_SIZE = int(cfg("FUZZ_MAX_SIZE", "8192"), 0)
except ValueError:
    FUZZ_MAX_SIZE = 8192
if FUZZ_MIN_SIZE < 1:
    FUZZ_MIN_SIZE = 1
if FUZZ_MAX_SIZE < FUZZ_MIN_SIZE:
    FUZZ_MAX_SIZE = FUZZ_MIN_SIZE
# =============================================================


def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


class ReportServer:
    def __init__(self, host, port, allowed_nets=None):
        self._host = host
        self._port = port
        # [Fix: P3] 접속 소스 제한용 허용 네트워크 목록. None/빈 리스트면 개방(하위 호환).
        self._allowed_nets = allowed_nets or []
        self._rejected_warned = set()  # 거부된 소스 IP 경고 1회 래치(로그 스팸 방지)
        self._lock = threading.Lock()
        self._srv = None
        self._running = False
        self._last_inioctl = None
        self._per_worker = {}
        # [Fix: P1] 워커별 "마지막 InIoctl 패킷"만 별도 추적(모든 phase를 담는 _per_worker와 구분).
        #   BSOD 확정 시 공동 후보 산출에 사용.
        self._per_worker_inioctl = {}
        self._saved_keys = set()
        self._round = 0
        self._pending_lock = threading.Lock()
        self._pending_fh = None
        self._last_inioctl_raw = None
        self._pending_mtime = 0.0
        self._round_total = 0
        self._round_inioctl = 0
        self._round_workers = set()

    def start(self):
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # [Fix: P3] 0.0.0.0(모든 인터페이스) 대신 게스트가 접속하는 vmnet 인터페이스에만 바인드 시도.
        #   지정 인터페이스 바인드가 실패하면(설정 오류 등) 서비스 지속을 위해 0.0.0.0로 폴백하고 경고한다.
        #   어느 경우든 아래 _accept_loop의 소스 IP 필터가 2차 방어선으로 동작한다.
        try:
            self._srv.bind((self._host, self._port))
        except OSError as e:
            log(f"[TCP][WARN] Bind to interface {self._host}:{self._port} failed ({e}); "
                f"falling back to 0.0.0.0. Source-IP filter still applies.")
            self._host = "0.0.0.0"
            self._srv.bind((self._host, self._port))
        self._srv.listen(64)
        self._running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        log(f"[TCP] Report server listening on {self._host}:{self._port} (record={RECORD_SIZE}B).")
        # [Fix: P3] 소스 제한 상태를 명시적으로 로깅해 운영 중 오탐/개방을 즉시 인지할 수 있게 한다.
        if self._allowed_nets:
            log(f"[TCP][SEC] Accepting reports only from: {', '.join(str(n) for n in self._allowed_nets)}")
        else:
            log("[TCP][SEC][WARN] Source restriction DISABLED (allow-all). "
                "Set ALLOWED_GUEST_IPS or HOST_IP_FOR_GUEST for lab isolation.")
        log("[TCP] 방화벽에서 이 포트의 인바운드(사설/도메인 네트워크)를 허용해야 게스트가 접속할 수 있습니다.")

    def begin_round(self, round_no):
        with self._lock:
            self._round = round_no
            self._last_inioctl = None
            self._last_inioctl_raw = None
            self._per_worker = {}
            self._per_worker_inioctl = {}  # [Fix: P1] 라운드마다 워커별 InIoctl 스냅샷 초기화
            self._round_total = 0
            self._round_inioctl = 0
            self._round_workers = set()
        self._reset_pending()

    def get_guilty(self):
        with self._lock:
            return dict(self._last_inioctl) if self._last_inioctl else None

    def round_stats(self):
        with self._lock:
            return {
                "total": self._round_total,
                "inioctl": self._round_inioctl,
                "workers": len(self._round_workers),
            }

    def _reset_pending(self):
        with self._pending_lock:
            self._pending_mtime = 0.0  
            if self._pending_fh is not None:
                try:
                    self._pending_fh.close()
                except OSError:
                    pass
                self._pending_fh = None
            try:
                if os.path.isfile(PENDING_SEED_PATH):
                    os.remove(PENDING_SEED_PATH)
            except OSError as e:
                log(f"[PENDING][WARN] Failed to reset pending seed file: {e}")

    def _write_pending(self, raw):
        with self._pending_lock:
            try:
                if self._pending_fh is None:
                    os.makedirs(os.path.dirname(PENDING_SEED_PATH), exist_ok=True)
                    self._pending_fh = open(PENDING_SEED_PATH, "wb", buffering=0)
                self._pending_fh.seek(0)
                self._pending_fh.write(raw)
                self._pending_fh.flush()
                self._pending_mtime = time.time()  
            except OSError as e:
                log(f"[PENDING][WARN] pending_seed.bin write failed: {e}")
                self._pending_fh = None

    def promote_pending_to_crash(self):
        raw = None
        with self._pending_lock:
            if self._pending_fh is not None:
                try:
                    self._pending_fh.close()
                except OSError:
                    pass
                self._pending_fh = None
            try:
                if os.path.isfile(PENDING_SEED_PATH):
                    with open(PENDING_SEED_PATH, "rb") as f:
                        raw = f.read()
            except OSError as e:
                log(f"[PROMOTE][WARN] Failed to read pending seed: {e}")
        if not raw or len(raw) < RECORD_SIZE:
            with self._lock:
                raw = self._last_inioctl_raw
        if not raw or len(raw) < RECORD_SIZE:
            return None
        pkt = self._parse(raw[:RECORD_SIZE])
        if pkt is None:
            return None

        key = ("bsod", pkt["worker_id"], pkt["ioctl"], pkt["seed"], pkt["exc_code"],
               hashlib.md5(pkt["payload"]).hexdigest())
        with self._lock:
            if key in self._saved_keys:
                return None
            self._saved_keys.add(key)

        try:
            os.makedirs(CRASH_DIR, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            seed_id = f"0x{pkt['seed']:08X}_{ts}"          
            bin_path = os.path.join(CRASH_DIR, f"crash_{seed_id}.bin")
            meta_path = os.path.join(CRASH_DIR, f"crash_{seed_id}.meta.txt")
            with open(bin_path, "wb") as f:
                f.write(pkt["payload"])                     
            meta_lines = [
                "type=host_bsod_capture(pending_seed.bin promoted)",
                f"workerId={pkt['worker_id']}",
                f"ioctl=0x{pkt['ioctl']:X}",
                f"seed=0x{pkt['seed']:08X}",
                f"declaredSize={pkt['decl_size']}",
                f"actualSize={pkt['actual_size']}",
                f"phase={PHASE_NAMES.get(pkt['phase'], pkt['phase'])}",
                f"exceptionCode=0x{pkt['exc_code']:08X}",
                f"iteration={pkt['iteration']}",
                f"payloadLen={pkt['payload_len']}",
                f"promotedFrom={PENDING_SEED_PATH}",
                f"capturedAt={datetime.now().isoformat()}",
            ]
            with open(meta_path, "w", encoding="utf-8") as f:
                f.write(chr(10).join(meta_lines) + chr(10))
        except OSError as e:
            log(f"[PROMOTE][ERROR] Failed to promote pending seed: {e}")
            return None

        log(f"[SAVED:BSOD(kernel)] {os.path.basename(bin_path)} | "
            f"worker {pkt['worker_id']} IOCTL 0x{pkt['ioctl']:X} seed 0x{pkt['seed']:08X} "
            f"size {pkt['decl_size']}B iter {pkt['iteration']} (promoted from pending_seed.bin)")
        return bin_path

    def wait_pending_settled(self, timeout=8.0, quiet=1.5):
        deadline = time.time() + max(0.0, timeout)
        while time.time() < deadline:
            with self._pending_lock:
                last = self._pending_mtime
            if last > 0 and (time.time() - last) >= quiet:
                return
            time.sleep(0.2)

    def close(self):
        with self._pending_lock:
            if self._pending_fh is not None:
                try:
                    self._pending_fh.close()
                except OSError:
                    pass
                self._pending_fh = None

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._srv.accept()
            except OSError:
                break
            # [Fix: P3] 매직 넘버(KTCP)는 위조 가능하므로, 접속 소스 IP를 게스트 대역으로 1차 차단한다.
            peer_ip = addr[0] if addr else ""
            if not self._is_allowed_source(peer_ip):
                if peer_ip not in self._rejected_warned:
                    self._rejected_warned.add(peer_ip)
                    log(f"[TCP][SEC] Rejected connection from disallowed source {peer_ip} "
                        f"(not in guest allow-list). Further warnings for this IP suppressed.")
                try:
                    conn.close()
                except OSError:
                    pass
                continue
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def _is_allowed_source(self, ip):
        # [Fix: P3] 허용 네트워크가 비어 있으면(설정 안 됨) 하위 호환을 위해 개방한다(경고는 start()에서 출력).
        if not self._allowed_nets:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._allowed_nets)

    @staticmethod
    def _recv_exact(conn, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None  
            buf.extend(chunk)
        return bytes(buf)

    @staticmethod
    def _parse(data):
        (magic, version, worker_id, phase, ioctl, seed,
         decl_size, actual_size, iteration, exc_code, payload_len, payload) = REPORT_STRUCT.unpack(data)
        if struct.pack("<I", magic) != REPORT_MAGIC:
            return None
        payload_len = min(payload_len, 256)
        return {
            "worker_id": worker_id, "phase": phase, "ioctl": ioctl, "seed": seed,
            "decl_size": decl_size, "actual_size": actual_size, "iteration": iteration,
            "exc_code": exc_code, "payload": payload[:payload_len], "payload_len": payload_len,
            "ts": time.time(),
        }

    def _handle(self, conn, addr):
        conn.settimeout(SOCKET_IDLE_TIMEOUT)
        wid = None
        try:
            while True:
                data = self._recv_exact(conn, RECORD_SIZE)
                if data is None:
                    break
                pkt = self._parse(data)
                if pkt is None:
                    continue
                wid = pkt["worker_id"]
                self._on_packet(pkt, data)   
        except (socket.timeout, OSError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _on_packet(self, pkt, raw):
        with self._lock:
            self._per_worker[pkt["worker_id"]] = pkt
            self._round_total += 1
            self._round_workers.add(pkt["worker_id"])
            if pkt["phase"] == PHASE_INIOCTL:
                self._round_inioctl += 1
                self._last_inioctl = pkt
                self._last_inioctl_raw = raw
                # [Fix: P1] 워커별 마지막 InIoctl 패킷 갱신(전역 1개 덮어쓰기와 별개로 보존).
                self._per_worker_inioctl[pkt["worker_id"]] = pkt
        if pkt["phase"] == PHASE_INIOCTL:
            self._write_pending(raw)
        if pkt["phase"] == PHASE_CRASHED:
            self._save_crash(pkt, kind="seh_user")

    def _save_crash(self, pkt, kind):
        key = (kind, pkt["worker_id"], pkt["ioctl"], pkt["seed"], pkt["exc_code"],
               hashlib.md5(pkt["payload"]).hexdigest())
        with self._lock:
            if key in self._saved_keys:
                return False
            self._saved_keys.add(key)

        try:
            os.makedirs(CRASH_DIR, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            stem = (f"host_{kind}_w{pkt['worker_id']}_ioctl0x{pkt['ioctl']:X}"
                    f"_seed0x{pkt['seed']:08X}_sz{pkt['decl_size']}_{ts}")
            bin_path = os.path.join(CRASH_DIR, stem + ".bin")
            meta_path = os.path.join(CRASH_DIR, stem + ".meta.txt")
            with open(bin_path, "wb") as f:
                f.write(pkt["payload"])
            with open(meta_path, "w", encoding="utf-8") as f:
                f.write(
                    f"type={'host_bsod_capture' if kind == 'bsod' else 'usermode_seh_capture'}\n"
                    f"workerId={pkt['worker_id']}\n"
                    f"ioctl=0x{pkt['ioctl']:X}\n"
                    f"seed=0x{pkt['seed']:08X}\n"
                    f"declaredSize={pkt['decl_size']}\n"
                    f"actualSize={pkt['actual_size']}\n"
                    f"phase={PHASE_NAMES.get(pkt['phase'], pkt['phase'])}\n"
                    f"exceptionCode=0x{pkt['exc_code']:08X}\n"
                    f"iteration={pkt['iteration']}\n"
                    f"payloadLen={pkt['payload_len']}\n"
                    f"capturedAt={datetime.now().isoformat()}\n"
                )
        except OSError as e:
            log(f"[SAVE][ERROR] Failed to persist crash bin: {e}")
            return False

        tag = "SEH(usermode)" if kind == "seh_user" else "BSOD(kernel)"
        log(f"[SAVED:{tag}] {os.path.basename(bin_path)} | "
            f"worker {pkt['worker_id']} IOCTL 0x{pkt['ioctl']:X} seed 0x{pkt['seed']:08X} "
            f"size {pkt['decl_size']}B exc 0x{pkt['exc_code']:08X} iter {pkt['iteration']}")
        return True

    def save_bsod_guilty(self, pkt):
        return self._save_crash(pkt, kind="bsod")

    def save_bsod_candidates(self, window_ms=BSOD_CANDIDATE_WINDOW_MS,
                             max_candidates=BSOD_CANDIDATE_MAX):
        # [Fix: P1] BSOD 확정 시 "전역 마지막 InIoctl 1개"만 유죄로 저장하던 레이스를 완화.
        #   멀티 워커 동시 실행 중에는 실제 크래시 유발 워커를 단정할 수 없으므로,
        #   프리즈 직전 InIoctl 중이던 워커들의 최근 패킷을 모두 "공동 후보"로 보존한다.
        #   최신 InIoctl 타임스탬프 기준 window_ms 이내의 워커만 포함(모두 게스트 프리즈로
        #   거의 동시에 멈춘 시점 근처). 이미 유죄로 승격/저장된 패킷은 _saved_keys로 중복 회피.
        with self._lock:
            snapshot = list(self._per_worker_inioctl.values())
        if not snapshot:
            return []
        newest_ts = max(pkt["ts"] for pkt in snapshot)
        window = max(0.0, window_ms) / 1000.0
        ordered = sorted(snapshot, key=lambda p: p["ts"], reverse=True)
        candidates = [pkt for pkt in ordered if (newest_ts - pkt["ts"]) <= window]
        candidates = candidates[:max(1, max_candidates)]
        total = len(candidates)
        saved = []
        for rank, pkt in enumerate(candidates, start=1):
            age_ms = int((newest_ts - pkt["ts"]) * 1000)
            path = self._persist_candidate(pkt, rank, total, age_ms)
            if path:
                saved.append(path)
        if saved:
            log(f"[BSOD][CAND] Saved {len(saved)} co-candidate seed(s) from {total} "
                f"InIoctl worker(s) within {window_ms}ms window.")
        return saved

    def _persist_candidate(self, pkt, rank, total, age_ms):
        # [Fix: P1] 개별 공동 후보를 crashes/ 아래 별도 파일(.bin + .meta.txt)로 저장.
        #   키는 유죄 승격과 동일 스킴("bsod", ...)을 써서, 이미 승격된 primary는 자동 스킵된다.
        key = ("bsod", pkt["worker_id"], pkt["ioctl"], pkt["seed"], pkt["exc_code"],
               hashlib.md5(pkt["payload"]).hexdigest())
        with self._lock:
            if key in self._saved_keys:
                return None
            self._saved_keys.add(key)
        try:
            os.makedirs(CRASH_DIR, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            stem = (f"bsod_cand{rank}of{total}_w{pkt['worker_id']}_ioctl0x{pkt['ioctl']:X}"
                    f"_seed0x{pkt['seed']:08X}_sz{pkt['decl_size']}_{ts}")
            bin_path = os.path.join(CRASH_DIR, stem + ".bin")
            meta_path = os.path.join(CRASH_DIR, stem + ".meta.txt")
            with open(bin_path, "wb") as f:
                f.write(pkt["payload"])
            meta_lines = [
                "type=host_bsod_candidate(per-worker InIoctl snapshot)",
                f"candidateRank={rank}/{total}",
                f"ageFromNewestMs={age_ms}",
                f"workerId={pkt['worker_id']}",
                f"ioctl=0x{pkt['ioctl']:X}",
                f"seed=0x{pkt['seed']:08X}",
                f"declaredSize={pkt['decl_size']}",
                f"actualSize={pkt['actual_size']}",
                f"phase={PHASE_NAMES.get(pkt['phase'], pkt['phase'])}",
                f"exceptionCode=0x{pkt['exc_code']:08X}",
                f"iteration={pkt['iteration']}",
                f"payloadLen={pkt['payload_len']}",
                f"capturedAt={datetime.now().isoformat()}",
            ]
            with open(meta_path, "w", encoding="utf-8") as f:
                f.write(chr(10).join(meta_lines) + chr(10))
        except OSError as e:
            log(f"[BSOD][CAND][ERROR] Failed to persist candidate: {e}")
            return None
        log(f"[SAVED:BSOD-CAND {rank}/{total}] {os.path.basename(bin_path)} | "
            f"worker {pkt['worker_id']} IOCTL 0x{pkt['ioctl']:X} seed 0x{pkt['seed']:08X} "
            f"size {pkt['decl_size']}B age {age_ms}ms iter {pkt['iteration']}")
        return bin_path


def detect_host_ip():
    if HOST_IP_FOR_GUEST:
        log(f"[NET] Using configured HOST_IP_FOR_GUEST = {HOST_IP_FOR_GUEST}")
        return HOST_IP_FOR_GUEST
    candidates = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in candidates and (ip.startswith("192.168.") or ip.startswith("172.") or ip.startswith("10.")):
                candidates.append(ip)
    except socket.gaierror:
        pass
    if not candidates:
        log("[NET][WARN] No private IPv4 found; falling back to 127.0.0.1.")
        return "127.0.0.1"
    chosen = candidates[0]
    log(f"[NET] Auto-detected host IP candidates {candidates} -> using {chosen}.")
    return chosen


def build_allowed_source_networks(host_ip):
    # [Fix: P3] 접속 허용 소스 네트워크 목록 구성(격리 랩 전제, stdlib ipaddress만 사용).
    #   - ALLOWED_GUEST_IPS가 지정되면 각 IP를 /32로 허용(가장 엄격).
    #   - 미지정 시 host_ip의 /24(vmnet 서브넷)를 허용 — 게스트는 호스트와 같은 vmnet 대역에 있다.
    #   - 유효 소스를 하나도 못 구하면 빈 리스트를 반환 -> 소스 제한 비활성(개방, 하위 호환).
    #   - 목록이 비어있지 않으면 루프백(127.0.0.0/8)을 항상 포함해 로컬 디버깅을 허용한다.
    nets = []
    if ALLOWED_GUEST_IPS:
        for ip in ALLOWED_GUEST_IPS:
            try:
                nets.append(ipaddress.ip_network(f"{ip}/32", strict=False))
            except ValueError:
                log(f"[SEC][WARN] Invalid ALLOWED_GUEST_IPS entry ignored: {ip}")
    else:
        # 명시 IP가 없으면 host_ip의 vmnet /24 대역을 허용(플레이스홀더/루프백은 제외).
        if host_ip and host_ip != "127.0.0.1" and not host_ip.startswith("Your"):
            try:
                nets.append(ipaddress.ip_network(f"{host_ip}/24", strict=False))
            except ValueError:
                log(f"[SEC][WARN] Could not derive guest subnet from host_ip={host_ip}.")
    if not nets:
        return []
    nets.append(ipaddress.ip_network("127.0.0.0/8"))
    return nets


def revert_vm():
    log(f"Reverting VM to snapshot: '{SNAPSHOT_NAME}'...")
    # [Fix: P0] 개별 vmrun 호출에 timeout을 부여해 스냅샷 락/행 상황에서 무한 블로킹을 차단.
    #   check=True는 유지 — 실패는 예외로 올리고, 호출부(revert_vm_with_retry)가 흡수/재시도한다.
    subprocess.run([VMRUN_PATH, "-vp", VM_ACCESS_PASS, "-T", "ws",
                    "revertToSnapshot", VMX_PATH, SNAPSHOT_NAME],
                   check=True, timeout=VM_OP_TIMEOUT)
    subprocess.run([VMRUN_PATH, "-vp", VM_ACCESS_PASS, "-T", "ws",
                    "start", VMX_PATH, "nogui"],
                   check=True, timeout=VM_OP_TIMEOUT)
    log("VM Revert & Power On completed.")


def revert_vm_with_retry():
    # [Fix: P0] revert_vm()의 CalledProcessError/TimeoutExpired/OSError를 흡수해 컨트롤러 생존을 보장.
    #   - 재시도 횟수 상한(VM_MAX_RETRIES) + 지수 백오프(VM_RETRY_BACKOFF)로 무한 재시도를 방지.
    #   - 모든 시도가 실패하면 False를 반환해 호출부(main 루프)가 이번 라운드를 안전하게 건너뛰도록 함.
    for attempt in range(1, VM_MAX_RETRIES + 1):
        try:
            revert_vm()
            return True
        except subprocess.TimeoutExpired:
            log(f"[VM][WARN] revert/start timed out (>{VM_OP_TIMEOUT}s) "
                f"(attempt {attempt}/{VM_MAX_RETRIES}).")
        except subprocess.CalledProcessError as e:
            log(f"[VM][WARN] vmrun revert/start failed rc={e.returncode} "
                f"(attempt {attempt}/{VM_MAX_RETRIES}).")
        except OSError as e:
            log(f"[VM][WARN] vmrun invocation error: {e} "
                f"(attempt {attempt}/{VM_MAX_RETRIES}).")
        if attempt < VM_MAX_RETRIES:
            backoff = VM_RETRY_BACKOFF * (2 ** (attempt - 1))
            log(f"[VM] Retrying VM revert in {backoff}s...")
            time.sleep(backoff)
    log(f"[VM][ERROR] VM revert failed after {VM_MAX_RETRIES} attempts. Skipping this round.")
    return False


def wait_for_tools():
    log("Waiting for VMware Tools to initialize inside Guest...")
    cmd = [VMRUN_PATH, "-vp", VM_ACCESS_PASS, "-T", "ws", "checkToolsState", VMX_PATH]
    for _ in range(30):
        try:
            res = subprocess.run(cmd, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", check=False)
            output = res.stdout.lower()
            if ("running" in output or "installed" in output) and "not running" not in output:
                log("VMware Tools is ready.")
                return True
        except Exception:
            pass
        time.sleep(1)
    log("[WARNING] VMware Tools wait timed out! Proceeding anyway...")
    return False


def guest_tools_alive():
    cmd = [VMRUN_PATH, "-vp", VM_ACCESS_PASS, "-T", "ws", "checkToolsState", VMX_PATH]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=30).stdout.lower()
        return ("running" in out) and ("not running" not in out)
    except Exception:
        return False


def confirm_guest_down(grace_seconds=BSOD_GRACE_SECONDS, poll=BSOD_GRACE_POLL,
                       healthy_streak=6, initial_settle=BSOD_INITIAL_SETTLE):
    settle_deadline = time.time() + max(0, initial_settle)
    while time.time() < settle_deadline:
        if not guest_tools_alive():
            return True          
        time.sleep(1)

    deadline = time.time() + max(0, grace_seconds)
    alive_run = 0
    while time.time() < deadline:
        if not guest_tools_alive():
            return True          
        alive_run += 1
        if alive_run >= healthy_streak:
            return False         
        time.sleep(poll)
    return not guest_tools_alive()


def stage_worker_to_local():
    if not os.path.isfile(HOST_WORKER_EXE):
        log(f"[STAGE][ERROR] Host worker exe not found: {HOST_WORKER_EXE}")
        return False

    mkdir_cmd = [
        VMRUN_PATH, "-vp", VM_ACCESS_PASS, "-T", "ws",
        "-gu", VM_USER, "-gp", VM_PASS,
        "createDirectoryInGuest", VMX_PATH, GUEST_LOCAL_DIR,
    ]
    try:
        mk = subprocess.run(mkdir_cmd, timeout=60, capture_output=True, text=True,
                            encoding="utf-8", errors="replace")
        if mk.returncode != 0:
            log(f"[STAGE] createDirectory rc={mk.returncode} (이미 존재 가능). "
                f"err={mk.stderr.strip()}")
    except subprocess.TimeoutExpired:
        log("[STAGE][WARN] createDirectory step timed out; attempting copy anyway.")

    copy_cmd = [
        VMRUN_PATH, "-vp", VM_ACCESS_PASS, "-T", "ws",
        "-gu", VM_USER, "-gp", VM_PASS,
        "copyFileFromHostToGuest", VMX_PATH, HOST_WORKER_EXE, GUEST_LOCAL_EXE,
    ]
    try:
        cp = subprocess.run(copy_cmd, timeout=120, capture_output=True, text=True,
                            encoding="utf-8", errors="replace")
        if cp.returncode == 0:
            log(f"[STAGE] Injected worker to {GUEST_LOCAL_EXE} (copyFileFromHostToGuest, UNC 회피).")
            return True
        log(f"[STAGE][WARN] copyFileFromHostToGuest failed (rc={cp.returncode}). "
            f"out={cp.stdout.strip()} err={cp.stderr.strip()}")
        return False
    except subprocess.TimeoutExpired:
        log("[STAGE][WARN] copyFileFromHostToGuest timed out; attempting to run anyway.")
        return False


def run_fuzzer_in_vm(base_seed, start_ioctl, host_ip, port):
    ioctl_disp = "RANDOM(corpus-guided)" if IOCTL_RANDOM else ",".join(f"0x{c:X}" for c in TARGET_IOCTLS)
    log(f"Starting Fuzzer inside VM... (base-seed 0x{base_seed:08X}, start-ioctl {start_ioctl}, "
        f"IOCTLs=[{ioctl_disp}], size-range={FUZZ_MIN_SIZE}..{FUZZ_MAX_SIZE}, report {host_ip}:{port})")

    stage_worker_to_local()

    # [수정] IOCTL 플래그 구성. base_seed(뮤테이션 시드)와 IOCTL은 완전히 분리되어 전달된다.
    #   - list 모드: TARGET_IOCTLS 를 --ioctl 로 명시(결정론적 검증 경로, 재현성 보존).
    #   - random 모드: --ioctl-random 만 전달하고 목록은 생략(워커가 코퍼스 기반으로 재현 가능하게 생성).
    ioctl_args = []
    if IOCTL_RANDOM:
        ioctl_args = ["--ioctl-random"]
    else:
        for code in TARGET_IOCTLS:
            ioctl_args += ["--ioctl", f"0x{code:X}"]
    size_args = ["--min-size", str(FUZZ_MIN_SIZE), "--max-size", str(FUZZ_MAX_SIZE)]

    cmd = [
        VMRUN_PATH, "-vp", VM_ACCESS_PASS, "-T", "ws",
        "-gu", VM_USER, "-gp", VM_PASS,
        "runProgramInGuest", VMX_PATH,
        "-interactive",
        GUEST_LOCAL_EXE,
        "--worker", "0",
        GUEST_LOCAL_DIR,
        f"0x{base_seed:08X}",
        str(start_ioctl),
        "--report-host", host_ip,
        "--report-port", str(port),
        *ioctl_args,
        *size_args,
    ]

    try:
        res = subprocess.run(cmd, timeout=HANG_TIMEOUT, capture_output=True, text=True,
                              encoding="utf-8", errors="replace")
        if res.stdout and res.stdout.strip():
            log(f"[vmrun stdout] {res.stdout.strip()}")
        if res.stderr and res.stderr.strip():
            log(f"[vmrun stderr] {res.stderr.strip()}")
        log(f"Fuzzer process exited (rc={res.returncode}).")
        
        # [추가된 로직] vmrun이 통신 절단(-1) 에러를 뱉으면 커널 크래시로 판정
        if res.returncode == 4294967295 or "Tools are not running" in res.stdout:
            return True
        return False
        
    except subprocess.TimeoutExpired:
        log("Fuzzer ran to HANG_TIMEOUT without BSOD (workers still cycling).")
        return False


def load_cursor():
    try:
        with open(CURSOR_PATH, "r", encoding="utf-8") as f:
            data = {}
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    data[k.strip()] = v.strip()
            start_ioctl = int(data.get("start_ioctl", "0"), 0)
            base_seed = int(data.get("base_seed", "0"), 0) & SEED_MASK
            log(f"Cursor loaded: start_ioctl={start_ioctl}, base_seed=0x{base_seed:08X}")
            return start_ioctl, base_seed
    except (OSError, ValueError):
        base_seed = random.randint(0, SEED_MASK)
        log(f"No cursor found. Initializing: start_ioctl=0, base_seed=0x{base_seed:08X}")
        return 0, base_seed


def save_cursor(start_ioctl, base_seed):
    try:
        with open(CURSOR_PATH, "w", encoding="utf-8") as f:
            f.write(f"start_ioctl={start_ioctl}\nbase_seed=0x{base_seed & SEED_MASK:08X}\n")
    except OSError as e:
        log(f"[WARN] Failed to persist cursor: {e}")


def ensure_firewall_inbound(port):
    rule_name = f"WinKernelFuzzer_TCP_{port}"
    manual = (f"netsh advfirewall firewall add rule name={rule_name} "
              f"dir=in action=allow protocol=TCP localport={port}")
    try:
        chk = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15)
        if chk.returncode == 0 and "No rules match" not in chk.stdout:
            log(f"[FW] Inbound rule already present: {rule_name} (TCP {port}).")
            return True
        add = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=in", "action=allow",
             "protocol=TCP", f"localport={port}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15)
        if add.returncode == 0:
            log(f"[FW] Added inbound allow rule: {rule_name} (TCP {port}).")
            return True
        log(f"[FW][WARN] Firewall rule add failed. rc={add.returncode}")
        return False
    except Exception as e:
        log(f"[FW][WARN] Firewall ensure failed: {e}")
        return False


def pull_guest_file(guest_path, host_path):
    cmd = [
        VMRUN_PATH, "-vp", VM_ACCESS_PASS, "-T", "ws",
        "-gu", VM_USER, "-gp", VM_PASS,
        "copyFileFromGuestToHost", VMX_PATH, guest_path, host_path,
    ]
    try:
        r = subprocess.run(cmd, timeout=60, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def log_guest_preflight_diag():
    pulled_any = False
    for guest_name in ("preflight_error.txt", "boot_stage.txt"):
        guest_path = GUEST_LOCAL_DIR + "\\" + guest_name
        host_path = os.path.join(HOST_SHARED_DIR, guest_name)
        if pull_guest_file(guest_path, host_path):
            pulled_any = True
            try:
                with open(host_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read().strip()
                log(f"[DIAG][GUEST] {guest_name} =>\n{content}")
            except OSError:
                log(f"[DIAG][GUEST] {guest_name} 회수했으나 읽기 실패.")
        else:
            log(f"[DIAG][GUEST] {guest_name} 게스트에 없음.")
    if not pulled_any:
        log("[DIAG][GUEST] 진단 파일을 하나도 회수하지 못함.")


def validate_config():
    # [Fix: P5] 필수 설정(자격 증명/경로)이 채워졌는지 검증. 누락 시 친절한 안내 후 종료.
    #   빈 값과 예시값('Your...'로 시작) 모두 '미설정'으로 취급해 실수로 예시 그대로 실행되는 것을 막는다.
    required = [
        ("VMX_PATH", VMX_PATH, "VM의 .vmx 파일 경로"),
        ("VM_PASS", VM_PASS, "게스트 로그인 비밀번호"),
        ("VM_ACCESS_PASS", VM_ACCESS_PASS, "vmrun 접근 비밀번호"),
        ("HOST_WORKER_EXE", HOST_WORKER_EXE, "호스트의 워커 exe 경로"),
        ("HOST_SHARED_DIR", HOST_SHARED_DIR, "크래시/시드 저장 디렉터리"),
    ]
    missing = [(k, d) for (k, v, d) in required if (not v) or str(v).startswith("Your")]
    if not missing:
        return
    log("[CONFIG][FATAL] 필수 설정이 비어 있거나 예시값 그대로입니다. 아래 항목을 채워주세요:")
    for k, d in missing:
        log(f"    - {k}  ({d})")
    if not os.path.isfile(ENV_FILE_PATH):
        log(f"[CONFIG] 설정 파일이 없습니다 -> {ENV_FILE_PATH}")
        log("[CONFIG] 템플릿을 복사한 뒤 값을 채우세요:")
        log(f'[CONFIG]     copy "{ENV_EXAMPLE_PATH}" "{ENV_FILE_PATH}"')
    else:
        log(f"[CONFIG] 설정 파일을 열어 값을 채우세요 -> {ENV_FILE_PATH}")
    log("[CONFIG] (또는 환경변수로 지정 가능:  set VM_PASS=...   set VM_ACCESS_PASS=... )")
    log("[CONFIG] 자격 증명은 절대 소스/깃에 커밋하지 마세요. fuzzer.env 는 .gitignore 로 제외됩니다.")
    sys.exit(1)


def main():
    log("=== WinKernel Fuzzer Controller (TCP IPC) Started ===")
    validate_config()  # [Fix: P5] 필수 설정 검증(누락 시 친절히 안내 후 종료)
    os.makedirs(CRASH_DIR, exist_ok=True)

    host_ip = detect_host_ip()
    ensure_firewall_inbound(LISTEN_PORT)
    # [Fix: P3] 0.0.0.0 전개방 대신 vmnet 인터페이스 바인드 + 게스트 소스 IP 필터를 적용한다.
    bind_host = host_ip if BIND_TO_HOST_IP else LISTEN_HOST
    allowed_nets = build_allowed_source_networks(host_ip)
    server = ReportServer(bind_host, LISTEN_PORT, allowed_nets)
    server.start()

    run_count = 0
    start_ioctl, base_seed = load_cursor()

    # [수정] 과거의 `base_seed = 0x222004` 강제 고정(테스트 해킹)을 제거했다.
    #   base_seed는 '뮤테이션 시드'이지 IOCTL 코드가 아니므로, 이 값을 0x222004로 둬도 IOCTL은 바뀌지 않았다.
    #   이제 타깃 IOCTL은 TARGET_IOCTLS 설정(fuzzer.env / 환경변수)으로 지정한다.
    #   - 음성 케이스 검증:  TARGET_IOCTLS=0x222004  (HEVD 미정의 -> 크래시 없어야 정상)
    #   - 양성(취약점) 재현: TARGET_IOCTLS=0x222003  (스택 오버플로우, 임계 크기 초과 시 크래시)
    ioctl_disp = "RANDOM(corpus-guided)" if IOCTL_RANDOM else ",".join(f"0x{c:X}" for c in TARGET_IOCTLS)
    log(f"[CFG] IOCTL mode={IOCTL_MODE} target=[{ioctl_disp}] | payload size-range={FUZZ_MIN_SIZE}..{FUZZ_MAX_SIZE} "
        f"(per-case actual IOCTL/size shown in [SAVED:...] crash lines) "
        f"| base-seed(mutation)=0x{base_seed:08X} | start-ioctl-idx={start_ioctl}")

    try:
        while True:
            run_count += 1
            log(f"\n--- Fuzzing Iteration #{run_count} ---")

            # [Fix: P0] revert 단계는 컨트롤러 생존의 급소이므로 재시도 래퍼로 감싼다.
            if not revert_vm_with_retry():
                log("[VM] Skipping this iteration due to VM revert failure.")
                time.sleep(VM_RETRY_BACKOFF)
                continue

            try:
                wait_for_tools()

                server.begin_round(run_count)
                vmrun_crashed = run_fuzzer_in_vm(base_seed, start_ioctl, host_ip, LISTEN_PORT)

                stats = server.round_stats()
                log(f"[ROUND] Received packets={stats['total']} (InIoctl={stats['inioctl']}) "
                    f"from {stats['workers']} worker(s).")

                time.sleep(2)
                
                # vmrun이 비정상 절단되었거나 게스트 툴이 응답하지 않으면 즉시 BSOD로 확정
                guest_down = vmrun_crashed or not guest_tools_alive() or confirm_guest_down()

                if stats['total'] == 0:
                    log("[DIAG][WARN] 이번 라운드 수신 패킷 0개 -> preflight 실패 또는 접속 실패 가능성 높음.")
                    log_guest_preflight_diag()
                elif guest_down:
                    server.wait_pending_settled()
                    saved = server.promote_pending_to_crash()
                    if saved:
                        log(f"[BSOD] Guest down. Promoted pending_seed.bin -> {os.path.basename(saved)}")
                    else:
                        guilty = server.get_guilty()
                        if guilty:
                            log(f"[BSOD] Guest down. Guilty candidate = "
                                f"worker {guilty['worker_id']} IOCTL 0x{guilty['ioctl']:X} "
                                f"seed 0x{guilty['seed']:08X} size {guilty['decl_size']}B")
                            server.save_bsod_guilty(guilty)
                        else:
                            log("[BSOD] Guest down but no pending seed / InIoctl this round.")
                    # [Fix: P1] 단일 유죄 승격과 별개로, 프리즈 직전 InIoctl 중이던 워커들을 공동 후보로 함께 보존한다.
                    server.save_bsod_candidates()
                else:
                    log("[OK] No BSOD this round.")

                base_seed = (base_seed + SEED_STRIDE) & SEED_MASK
                save_cursor(start_ioctl, base_seed)
            except Exception as e:
                # [Fix: P0] 한 라운드의 실패가 컨트롤러 전체를 죽이지 않도록 흡수하고 다음 라운드로 진행.
                log(f"[ROUND][ERROR] Unexpected failure during iteration #{run_count}: {e!r}. "
                    f"Continuing to next round.")
                time.sleep(VM_RETRY_BACKOFF)
                continue

    except KeyboardInterrupt:
        log("\nController stopped by user (Ctrl+C). Exiting safely.")
    finally:
        server.close()


if __name__ == "__main__":
    main()