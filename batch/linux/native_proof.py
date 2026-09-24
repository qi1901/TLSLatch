import atexit
import ctypes as C
import os
from pathlib import Path
import sys
import subprocess


class NativeProof:
    def __init__(self, reporter):
        self.reporter = reporter
        self.closed = False
        self.mac = sys.platform == "darwin"
        self.worker = None
        if sys.platform.startswith("linux"):
            self.backend = "persistent-native-helper"
            self.worker = subprocess.Popen(
                [
                    str(Path(__file__).with_name("proof_worker")),
                    "generate" if reporter else "verify",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
            if self._read(1) != b"\x01":
                raise RuntimeError("native proof worker initialization failed")
            atexit.register(self.close)
            return
        if self.mac:
            self.backend = "in-process-native"
            if reporter:
                raise RuntimeError("macOS is verifier-only")
            self.lib = C.CDLL(os.environ["TCPRA_VERIFY_DYLIB"])
            self.verify = self.lib.tcpra_verify
            self.verify.argtypes = [C.c_void_p] * 4
            self.verify.restype = C.c_int32
            self.pek = bytes.fromhex(os.environ["CSV_RA_TRUSTED_PEK"])
            self.measure = bytes.fromhex(os.environ["CSV_RA_TRUSTED_MEASURE"])
            if len(self.pek) != 64 or len(self.measure) != 32:
                raise ValueError("invalid trust anchors")
            return
        self.backend = "in-process-native"
        name = "proof_bridge.dll" if os.name == "nt" else "libproof_bridge.so"
        self.lib = C.CDLL(str(Path(__file__).with_name(name)))
        self.lib.tcpra_bridge_init.argtypes = [C.c_int]
        self.lib.tcpra_bridge_init.restype = C.c_int
        self.lib.tcpra_bridge_verify.argtypes = [C.c_void_p, C.c_void_p]
        self.lib.tcpra_bridge_verify.restype = C.c_int
        self.lib.tcpra_bridge_close.argtypes = []
        self.lib.tcpra_bridge_close.restype = None
        if self.lib.tcpra_bridge_init(int(reporter)) != 1:
            raise RuntimeError("native CSV initialization failed")
        if reporter:
            self.lib.tcpra_bridge_generate.argtypes = [C.c_void_p, C.c_void_p]
            self.lib.tcpra_bridge_generate.restype = C.c_int
        atexit.register(self.close)

    def _read(self, n):
        data = b""
        while len(data) < n:
            part = self.worker.stdout.read(n - len(data))
            if not part:
                raise RuntimeError("native proof worker closed its response pipe")
            data += part
        return data

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.worker is not None:
            try:
                self.worker.stdin.write(b"Q")
                self.worker.stdin.flush()
                self.worker.stdin.close()
                code = self.worker.wait(timeout=10)
            except BaseException:
                if self.worker.poll() is None:
                    self.worker.kill()
                    self.worker.wait()
                raise
            finally:
                self.worker.stdout.close()
            if code:
                raise RuntimeError("native proof worker exit code " + str(code))
        elif not self.mac:
            self.lib.tcpra_bridge_close()

    def __call__(self, mode, digest, path):
        binding = bytes.fromhex(digest)
        if self.closed:
            raise RuntimeError("proof context already closed")
        if len(binding) != 64:
            raise ValueError("binding must contain 64 bytes")
        key = C.create_string_buffer(binding, 64)
        path = Path(path)
        if self.worker is not None:
            if mode == "generate":
                if not self.reporter:
                    raise ValueError("verifier cannot generate")
                payload = b"G" + binding
            elif mode == "verify":
                report = path.read_bytes()
                if len(report) != 2548:
                    raise ValueError("report must contain exactly 2548 bytes")
                payload = b"V" + binding + report
            else:
                raise ValueError("unknown proof operation")
            self.worker.stdin.write(payload)
            self.worker.stdin.flush()
            if self._read(1) != b"\x01":
                raise RuntimeError("native " + mode + " failed")
            if mode == "generate":
                report = self._read(2548)
                with path.open("xb") as f:
                    f.write(report)
            return
        if mode == "generate":
            if not self.reporter:
                raise ValueError("verifier cannot generate")
            report = C.create_string_buffer(2548)
            if self.lib.tcpra_bridge_generate(key, report) != 1:
                raise RuntimeError("native report generation failed")
            with path.open("xb") as f:
                f.write(report.raw)
        elif mode == "verify":
            data = path.read_bytes()
            if len(data) != 2548:
                raise ValueError("report must contain exactly 2548 bytes")
            report = C.create_string_buffer(data, 2548)
            if self.mac:
                ok = self.verify(
                    report,
                    key,
                    C.create_string_buffer(self.pek, 64),
                    C.create_string_buffer(self.measure, 32),
                )
            else:
                ok = self.lib.tcpra_bridge_verify(report, key)
            if ok != 1:
                raise RuntimeError("native report verification failed")
        else:
            raise ValueError("unknown proof operation")
