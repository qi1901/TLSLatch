import ctypes as C
import ctypes.util
import struct
import threading
import time
import hashlib
import socket
import json
import sys


class Header(C.Structure):
    _fields_ = [
        ("tv_sec", C.c_long),
        ("tv_usec", C.c_long),
        ("caplen", C.c_uint32),
        ("length", C.c_uint32),
    ]


class BPF(C.Structure):
    _fields_ = [("length", C.c_uint), ("insns", C.c_void_p)]


class Stats(C.Structure):
    _fields_ = [("recv", C.c_uint), ("drop", C.c_uint), ("ifdrop", C.c_uint)]


def parse(packet):
    if len(packet) < 14:
        return None
    offset = 14
    proto = struct.unpack("!H", packet[12:14])[0]
    while proto in (0x8100, 0x88A8):
        if len(packet) < offset + 4:
            return None
        proto = struct.unpack("!H", packet[offset + 2 : offset + 4])[0]
        offset += 4
    if proto != 0x800:
        return None
    ip = packet[offset:]
    ihl = (ip[0] & 15) * 4
    if len(ip) < 20 or ihl < 20 or ip[9] != 6 or struct.unpack("!H", ip[6:8])[0] & 0x3FFF:
        return None
    total = struct.unpack("!H", ip[2:4])[0]
    tcp = ip[ihl:total]
    if len(tcp) < 20:
        return None
    off = (tcp[12] >> 4) * 4
    payload = tcp[off:]
    if len(payload) < 9 or payload[0] != 22 or payload[5] != 2:
        return None
    n = 5 + struct.unpack("!H", payload[3:5])[0]
    if n > len(payload):
        raise ValueError("split/truncated SH: unsupported in this bounded validation")
    sh = payload[:n]
    handshake_n = int.from_bytes(sh[6:9], "big")
    if handshake_n + 9 != n or len(sh) < 44:
        raise ValueError("invalid SH length")

    random = sh[11:43]
    if random.hex() == "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c":
        return None
    j = 44 + sh[43] + 3
    if j + 2 > len(sh):
        raise ValueError("invalid SH fields")
    end = j + 2 + int.from_bytes(sh[j : j + 2], "big")
    j += 2
    found = False
    if end != n:
        raise ValueError("invalid SH extensions")
    while j < end:
        if j + 4 > end:
            raise ValueError("extension header")
        kind, length = struct.unpack("!HH", sh[j : j + 4])
        j += 4
        v = sh[j : j + length]
        j += length
        if j > end:
            raise ValueError("extension bounds")
        if kind == 51:
            if len(v) < 4 or int.from_bytes(v[2:4], "big") != len(v) - 4:
                raise ValueError("not a final key share")
            found = True
    if not found:
        return None

    return {
        "id": hashlib.sha256(b"tcpra/batch-sh/leaf/v1\0" + sh).hexdigest(),
        "server": socket.inet_ntoa(ip[12:16]),
        "client": socket.inet_ntoa(ip[16:20]),
        "server_port": int.from_bytes(tcp[:2], "big"),
        "client_port": int.from_bytes(tcp[2:4], "big"),
        "observed_ns": time.monotonic_ns(),
    }


class Observer:
    def __init__(self, iface, server, client, outbound, main_port=19443):
        self.lib = C.CDLL(
            "/usr/lib/libpcap.dylib" if sys.platform == "darwin" else "/usr/lib64/libpcap.so.1"
        )
        l = self.lib
        signatures = {
            "pcap_create": ([C.c_char_p, C.c_char_p], C.c_void_p),
            "pcap_activate": ([C.c_void_p], C.c_int),
            "pcap_datalink": ([C.c_void_p], C.c_int),
            "pcap_compile": (
                [C.c_void_p, C.POINTER(BPF), C.c_char_p, C.c_int, C.c_uint32],
                C.c_int,
            ),
            "pcap_setfilter": ([C.c_void_p, C.POINTER(BPF)], C.c_int),
            "pcap_next_ex": (
                [C.c_void_p, C.POINTER(C.POINTER(Header)), C.POINTER(C.POINTER(C.c_ubyte))],
                C.c_int,
            ),
            "pcap_stats": ([C.c_void_p, C.POINTER(Stats)], C.c_int),
            "pcap_close": ([C.c_void_p], None),
            "pcap_freecode": ([C.POINTER(BPF)], None),
        }
        for name in [
            "snaplen",
            "promisc",
            "timeout",
            "immediate_mode",
            "buffer_size",
            "direction",
            "nonblock",
        ]:
            if name != "nonblock":
                signatures["pcap_set_" + name] = ([C.c_void_p, C.c_int], C.c_int)
        signatures["pcap_setdirection"] = signatures.pop("pcap_set_direction")
        for name, (args, res) in signatures.items():
            fn = getattr(l, name)
            fn.argtypes = args
            fn.restype = res
        err = C.create_string_buffer(256)
        self.handle = l.pcap_create(iface.encode(), err)
        if not self.handle:
            raise RuntimeError(err.value)
        for name, val in [
            ("snaplen", 4096),
            ("promisc", 0),
            ("timeout", 100),
            ("immediate_mode", 1),
            ("buffer_size", 67108864),
        ]:
            assert getattr(l, "pcap_set_" + name)(self.handle, val) == 0
        assert (
            l.pcap_activate(self.handle) >= 0 and l.pcap_datalink(self.handle) == 1
        ), "requires Ethernet capture"
        assert l.pcap_setdirection(self.handle, 2 if outbound else 1) == 0
        filt = f"ip and tcp and src host {server} and dst host {client} and src port {main_port} and tcp[((tcp[12]&0xf0)>>2)]=22 and tcp[((tcp[12]&0xf0)>>2)+5]=2"
        b = BPF()
        assert l.pcap_compile(self.handle, C.byref(b), filt.encode(), 1, 0xFFFFFFFF) == 0
        assert l.pcap_setfilter(self.handle, C.byref(b)) == 0
        l.pcap_freecode(C.byref(b))
        self.rows = {}
        self.lock = threading.Lock()
        self.error = None
        self.filter = filt
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def loop(self):
        try:
            h = C.POINTER(Header)()
            b = C.POINTER(C.c_ubyte)()
            while True:
                n = self.lib.pcap_next_ex(self.handle, C.byref(h), C.byref(b))
                if n == 0:
                    continue
                if n < 0:
                    raise RuntimeError("pcap read failed")
                row = parse(C.string_at(b, h.contents.caplen))
                if row:
                    with self.lock:
                        self.rows.setdefault(row["id"], row)
        except Exception as e:
            self.error = repr(e)

    def snapshot(self):
        if self.error:
            raise RuntimeError(self.error)
        with self.lock:
            return dict(self.rows)

    def save(self, path):
        rows = self.snapshot()
        st = Stats()
        assert self.lib.pcap_stats(self.handle, C.byref(st)) == 0
        path.write_text(
            json.dumps(
                {
                    "records": rows,
                    "pcap_received": st.recv,
                    "pcap_dropped": st.drop,
                    "pcap_ifdrop": st.ifdrop,
                    "filter": self.filter,
                    "error": self.error,
                },
                indent=2,
            )
            + "\n"
        )
        assert st.drop == 0 and st.ifdrop == 0
