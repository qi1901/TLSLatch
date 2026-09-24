#!/usr/bin/env python3

import pathlib
import plistlib
import subprocess
import shutil
import os
import json
import ipaddress
import re

root = pathlib.Path(__file__).resolve().parent
config = json.loads(pathlib.Path(os.environ["TLSLATCH_CONFIG"]).read_text())
ipaddress.IPv4Address(config["server_ip"])
for key, size in [("trusted_pek", 128), ("trusted_measurement", 64)]:
    if not re.fullmatch("[0-9a-fA-F]{%d}" % size, config[key]):
        raise ValueError("Invalid " + key)
for key in ["main_port", "control_port"]:
    if type(config[key]) is not int or not 1 <= config[key] <= 65535:
        raise ValueError("Invalid " + key)
if config["main_port"] == config["control_port"]:
    raise ValueError("Ports must differ")
identity = os.environ["CODESIGN_IDENTITY"]
(root / "build").mkdir(exist_ok=True)
deployment = root / "build/Deployment.swift"
deployment.write_text(
    "enum Deployment {\n"
    + "static let serverIP = "
    + json.dumps(config["server_ip"])
    + "\n"
    + "static let mainPort: UInt16 = "
    + str(config["main_port"])
    + "\n"
    + "static let controlPort: UInt16 = "
    + str(config["control_port"])
    + "\n"
    + "static let trustedPEK = "
    + json.dumps(config["trusted_pek"])
    + "\n"
    + "static let trustedMeasurement = "
    + json.dumps(config["trusted_measurement"])
    + "\n}\n"
)
app = root / "build/TcpraLocal.app"
ext = app / "Contents/Library/SystemExtensions/com.qi.tcpra.local.filter.systemextension"


def bundle(path, ident, name, extra):
    (path / "Contents/MacOS").mkdir(parents=True, exist_ok=True)
    info = dict(
        CFBundleIdentifier=ident,
        CFBundleName=name,
        CFBundleExecutable=name,
        CFBundleVersion="9",
        CFBundleShortVersionString="0.9",
        CFBundlePackageType="APPL" if path == app else "SYSX",
        LSMinimumSystemVersion="13.0",
        **extra
    )
    (path / "Contents/Info.plist").write_bytes(plistlib.dumps(info))


bundle(
    app,
    "com.qi.tcpra.local",
    "TcpraLocal",
    dict(NSSystemExtensionUsageDescription="TLSLatch network attestation"),
)
bundle(
    ext,
    "com.qi.tcpra.local.filter",
    "TcpraFilter",
    dict(
        NetworkExtension={
            "NEProviderClasses": {
                "com.apple.networkextension.filter-data": "TcpraFilter.FilterDataProvider"
            }
        },
        NSSystemExtensionUsageDescription="Local TCPRA content filter",
        OSBundleUsageDescription="Local TCPRA content filter",
    ),
)
common = {
    "com.apple.developer.networking.networkextension": ["content-filter-provider-systemextension"]
}
(ext / "Contents/Frameworks").mkdir(exist_ok=True)
library = ext / "Contents/Frameworks/libtcpra_pf_ffi.dylib"
shutil.copy(
    os.environ.get("TCPRA_FFI_LIBRARY", str(root / "ffi/target/release/libtcpra_pf_ffi.dylib")),
    library,
)
subprocess.run(["codesign", "--force", "--sign", identity, str(library)], check=True)
host = {**common, "com.apple.developer.system-extension.install": True}
for name, path, source, module, entitlements in [
    ("provider", ext, "Provider.swift", "TcpraFilter", common),
    ("host", app, "Host.swift", "TcpraLocal", host),
]:
    exe = path / "Contents/MacOS" / ("TcpraFilter" if name == "provider" else "TcpraLocal")
    source_path = root / source
    if name == "provider":

        source_path = root / "build/provider/main.swift"
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text((root / source).read_text())
    subprocess.run(
        [
            "xcrun",
            "swiftc",
            "-O",
            "-swift-version",
            "5",
            "-module-name",
            module,
            str(source_path),
            *([str(deployment)] if name == "provider" else []),
            "-o",
            str(exe),
            "-framework",
            "NetworkExtension",
            "-framework",
            "SystemExtensions",
        ],
        check=True,
    )
    ent = root / "build" / (name + ".entitlements")
    ent.write_bytes(plistlib.dumps(entitlements))
    subprocess.run(
        ["codesign", "--force", "--sign", identity, "--entitlements", str(ent), str(path)],
        check=True,
    )
print(app)
