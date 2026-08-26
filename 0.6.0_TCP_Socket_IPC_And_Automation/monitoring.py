import os
import socket
import struct
import subprocess
import threading
import time
import random
import hashlib
from datetime import datetime

#  WinKernel Fuzzer Controller  (TCP Socket IPC 재설계)

# ================= VM / vmrun Config =================
VMRUN_PATH = r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
VMX_PATH = r"Your\Path\To\win11_VM\Windows 11 x64.vmx"
SNAPSHOT_NAME = "set_host"
VM_USER = "Administrator"
VM_PASS = "YourPassword"
VM_ACCESS_PASS = "YourVmrunPassword"

# [Fix: 내장 Administrator 계정 권장 안내]
# 만약 여전히 rc=1이 발생한다면 VM 내 계정을 내장 'Administrator'로 변경하거나 
# VM_USER = "Administrator" 로 수정하여 UAC 토큰 필터링을 우회하세요.

# 호스트 로컬 exe 경로 및 게스트 스테이징 경로
HOST_WORKER_EXE = r"Your\Path\To\VM_Shared_Folder\YourProjectName.exe"
GUEST_LOCAL_DIR = r"C:\Fuzz"
GUEST_LOCAL_EXE = r"C:\Fuzz\YourProjectName.exe"

HANG_TIMEOUT = 300  
BSOD_GRACE_SECONDS = 180  
BSOD_GRACE_POLL = 5       
BSOD_INITIAL_SETTLE = 10  

# ================= 크래시 시드 영속(호스트 로컬) =================
HOST_SHARED_DIR = r"Your\Path\To\VM_Shared_Folder"
CRASH_DIR = os.path.join(HOST_SHARED_DIR, "crashes")  
PENDING_SEED_PATH = os.path.join(HOST_SHARED_DIR, "pending_seed.bin")

# ================= TCP IPC Config =================
LISTEN_HOST = "0.0.0.0"   
LISTEN_PORT = 51337       
HOST_IP_FOR_GUEST = "YourHostIP"  # 예: "192.168.175.1"

REPORT_STRUCT = struct.Struct("<8IQ2I256s")
RECORD_SIZE = REPORT_STRUCT.size  
REPORT_MAGIC = b"KTCP"            
PHASE_INIT, PHASE_PREIOCTL, PHASE_INIOCTL, PHASE_POSTIOCTL, PHASE_COMPLETED, PHASE_CRASHED = range(6)
PHASE_NAMES = {0: "Init", 1: "PreIoctl", 2: "InIoctl", 3: "PostIoctl", 4: "Completed", 5: "Crashed"}

SOCKET_IDLE_TIMEOUT = 30  

# ================= 호스트 주도 결정론 커서 =================
CURSOR_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fuzz_cursor.txt")
SEED_STRIDE = 256          
SEED_MASK = 0xFFFFFFFF
# =========================================================


def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


class ReportServer:
    def __init__(self, host, port):
        self._host = host
        self._port = port
        self._lock = threading.Lock()
        self._srv = None
        self._running = False
        self._last_inioctl = None
        self._per_worker = {}
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
        self._srv.bind((self._host, self._port))
        self._srv.listen(64)
        self._running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        log(f"[TCP] Report server listening on {self._host}:{self._port} (record={RECORD_SIZE}B).")
        log("[TCP] 방화벽에서 이 포트의 인바운드(사설/도메인 네트워크)를 허용해야 게스트가 접속할 수 있습니다.")

    def begin_round(self, round_no):
        with self._lock:
            self._round = round_no
            self._last_inioctl = None
            self._last_inioctl_raw = None
            self._per_worker = {}
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
            f"iter {pkt['iteration']} (promoted from pending_seed.bin)")
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
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

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
            f"exc 0x{pkt['exc_code']:08X} iter {pkt['iteration']}")
        return True

    def save_bsod_guilty(self, pkt):
        return self._save_crash(pkt, kind="bsod")


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


def revert_vm():
    log(f"Reverting VM to snapshot: '{SNAPSHOT_NAME}'...")
    subprocess.run([VMRUN_PATH, "-vp", VM_ACCESS_PASS, "-T", "ws",
                    "revertToSnapshot", VMX_PATH, SNAPSHOT_NAME], check=True)
    subprocess.run([VMRUN_PATH, "-vp", VM_ACCESS_PASS, "-T", "ws",
                    "start", VMX_PATH, "nogui"], check=True)
    log("VM Revert & Power On completed.")


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
    log(f"Starting Fuzzer inside VM... (base-seed 0x{base_seed:08X}, start-ioctl {start_ioctl}, "
        f"report {host_ip}:{port})")

    stage_worker_to_local()

    # [Fix: 작업 디렉터리를 C:\Fuzz로 명시 이동하여 수동 실행과 100% 동일한 환경 보장]
    guest_cmd = (
        f'cd /d {GUEST_LOCAL_DIR} && "{GUEST_LOCAL_EXE}" {host_ip} {port} 0x{base_seed:08X} {start_ioctl}'
    )

    cmd = [
        VMRUN_PATH, "-vp", VM_ACCESS_PASS, "-T", "ws",
        "-gu", VM_USER, "-gp", VM_PASS,
        "runProgramInGuest", VMX_PATH,
        "-interactive",  
        GUEST_LOCAL_EXE,
        host_ip,
        str(port),
        f"0x{base_seed:08X}",
        str(start_ioctl)
    ]

    try:
        res = subprocess.run(cmd, timeout=HANG_TIMEOUT, capture_output=True, text=True,
                              encoding="utf-8", errors="replace")
        if res.stdout and res.stdout.strip():
            log(f"[vmrun stdout] {res.stdout.strip()}")
        if res.stderr and res.stderr.strip():
            log(f"[vmrun stderr] {res.stderr.strip()}")
        log(f"Fuzzer process exited (rc={res.returncode}).")
    except subprocess.TimeoutExpired:
        log("Fuzzer ran to HANG_TIMEOUT without BSOD (workers still cycling).")


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


def main():
    log("=== WinKernel Fuzzer Controller (TCP IPC) Started ===")
    os.makedirs(CRASH_DIR, exist_ok=True)

    host_ip = detect_host_ip()
    ensure_firewall_inbound(LISTEN_PORT)  
    server = ReportServer(LISTEN_HOST, LISTEN_PORT)
    server.start()

    run_count = 0
    start_ioctl, base_seed = load_cursor()

    try:
        while True:
            run_count += 1
            log(f"\n--- Fuzzing Iteration #{run_count} ---")

            revert_vm()
            wait_for_tools()

            server.begin_round(run_count)
            run_fuzzer_in_vm(base_seed, start_ioctl, host_ip, LISTEN_PORT)

            stats = server.round_stats()
            log(f"[ROUND] Received packets={stats['total']} (InIoctl={stats['inioctl']}) "
                f"from {stats['workers']} worker(s).")

            time.sleep(2)
            if stats['total'] == 0:
                log("[DIAG][WARN] 이번 라운드 수신 패킷 0개 -> preflight 실패 또는 접속 실패 가능성 높음.")
                log_guest_preflight_diag()
            elif confirm_guest_down():
                server.wait_pending_settled()
                saved = server.promote_pending_to_crash()
                if saved:
                    log(f"[BSOD] Guest down. Promoted pending_seed.bin -> {os.path.basename(saved)}")
                else:
                    guilty = server.get_guilty()   
                    if guilty:
                        log(f"[BSOD] Guest down. Guilty candidate = "
                            f"worker {guilty['worker_id']} IOCTL 0x{guilty['ioctl']:X} "
                            f"seed 0x{guilty['seed']:08X}")
                        server.save_bsod_guilty(guilty)
                    else:
                        log("[BSOD] Guest down but no pending seed / InIoctl this round.")
            else:
                log("[OK] No BSOD this round.")

            base_seed = (base_seed + SEED_STRIDE) & SEED_MASK
            save_cursor(start_ioctl, base_seed)

    except KeyboardInterrupt:
        log("\nController stopped by user (Ctrl+C). Exiting safely.")
    finally:
        server.close()   


if __name__ == "__main__":
    main()