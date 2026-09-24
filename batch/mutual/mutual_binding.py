import hashlib
import json


def client_binding(manifest):
    return hashlib.sha512(
        b"tcpra/mutual-batch/client/v1\0"
        + json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def server_binding(manifest, client_report):
    return hashlib.sha512(
        b"tcpra/mutual-batch/server/v1\0"
        + bytes.fromhex(client_binding(manifest))
        + hashlib.sha256(client_report).digest()
    ).hexdigest()
