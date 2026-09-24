import Foundation
import NetworkExtension
import os
import Darwin

typealias HelloFn = @convention(c) (UnsafeRawPointer?, Int, Bool, UnsafeMutableRawPointer?) -> Int32
typealias VerifyFn = @convention(c) (
    UnsafeRawPointer?,
    UnsafeRawPointer?,
    UnsafeRawPointer?,
    UnsafeRawPointer?
) -> Int32
let lib = dlopen(Bundle.main.bundlePath + "/Contents/Frameworks/libtcpra_pf_ffi.dylib", RTLD_NOW)!
let helloFn = unsafeBitCast(dlsym(lib, "tcpra_hello"), to: HelloFn.self)
let verifyFn = unsafeBitCast(dlsym(lib, "tcpra_verify"), to: VerifyFn.self)
func hexData(_ s: String) -> Data {
    var d = Data()
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        d.append(UInt8(s[i ..< j], radix: 16)!)
        i = j
    }
    return d
}

func key(_ data: Data, _ client: Bool) -> Data? {
    var out = Data(count: 64)
    let rc = data.withUnsafeBytes { b in
        out.withUnsafeMutableBytes { o in
            helloFn(
                b.baseAddress,
                data.count,
                client,
                o.baseAddress
            )
        }
    }
    return rc == 1 ? out : nil
}

func hexOut(_ d: Data?) -> String {
    guard let d = d else {
        return ""
    }
    return d.map {
        String(format: "%02x", $0)
    }.joined()
}

final class FlowState {
    let condition = NSCondition()
    var lookup: Data?
    var binder: Data?
    var decision: Bool?
    var paused = false
    var inboundDone = false
    var outboundDone = false
    var tCh: UInt64 = 0
    var tSh: UInt64 = 0
    var recorded = false
    let deadline = Date().addingTimeInterval(5)
    func waitBinder() -> Data? {
        condition.lock()
        defer {
            condition.unlock()
        }
        while binder == nil && decision == nil {
            if !condition.wait(until: deadline) {
                break
            }
        }
        return binder
    }
}

func exchange(
    _ lookup: Data,
    _ state: FlowState,
    _ fault: String,
    _ event: (String) -> Void
) -> Bool {
    let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
    guard fd >= 0 else {
        return false
    }
    defer {
        Darwin.close(fd)
    }
    var noSignal: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
    let flags = fcntl(fd, F_GETFL, 0)
    guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else {
        return false
    }
    func ready(_ events: Int16) -> Bool {
        while true {
            let remaining = state.deadline.timeIntervalSinceNow
            guard remaining > 0 else {
                return false
            }
            var p = pollfd(fd: fd, events: events, revents: 0)
            let rc = Darwin.poll(&p, 1, Int32(min(remaining * 1000, 5000)))
            if rc < 0 && errno == EINTR {
                continue
            }
            return rc > 0 && p.revents & events != 0
        }
    }
    var tv = timeval(tv_sec: 5, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout.size(ofValue: tv)))
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout.size(ofValue: tv)))
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = Deployment.controlPort.bigEndian
    inet_pton(AF_INET, Deployment.serverIP, &address.sin_addr)
    let connected = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(
            to: sockaddr.self,
            capacity: 1
        ) {
            Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard connected == 0 || (errno == EINPROGRESS && ready(Int16(POLLOUT))) else {
        return false
    }
    var socketError: Int32 = 0
    var errorSize = socklen_t(MemoryLayout<Int32>.size)
    guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &errorSize) == 0,
          socketError == 0 else {
        return false
    }
    func writeAll(_ d: Data) -> Bool {
        d.withUnsafeBytes { b in
            var n = 0
            while n < d.count {
                guard ready(Int16(POLLOUT)) else {
                    return false
                }
                let r = Darwin.send(fd, b.baseAddress!.advanced(by: n), d.count - n, 0)
                if r < 0 && (errno == EINTR || errno == EAGAIN) {
                    continue
                }
                if r <= 0 {
                    return false
                }
                n += r
            }
            return true
        }
    }
    func readAll(_ count: Int) -> Data? {
        var d = Data(count: count)
        let ok = d.withUnsafeMutableBytes { b in
            var n = 0
            while n < count {
                guard ready(Int16(POLLIN)) else {
                    return false
                }
                let r = Darwin.recv(fd, b.baseAddress!.advanced(by: n), count - n, 0)
                if r < 0 && (errno == EINTR || errno == EAGAIN) {
                    continue
                }
                if r <= 0 {
                    return false
                }
                n += r
            }
            return true
        }
        return ok ? d : nil
    }
    var nonce = Data(count: 8)
    nonce.withUnsafeMutableBytes {
        arc4random_buf($0.baseAddress, 8)
    }
    guard writeAll(Data([0x43, 0x53, 0x56, 0x31, 0, 5, 0, 1]) + lookup + nonce)
    else {
        return false
    }
    event("REQUEST_SENT")
    guard let h = readAll(88), h.prefix(16) == Data([
        0x43,
        0x53,
        0x56,
        0x31,
        0,
        5,
        0,
        2,
        0,
        0,
        0,
        0,
        0,
        0,
        9,
        244
    ]), var report = readAll(2548) else {
        return false
    }
    event("REPORT_RECEIVED")
    guard var binder = state.waitBinder() else {
        return false
    }
    if fault == "delay" {
        Thread.sleep(forTimeInterval: 0.1)
    }
    if fault == "binder" {
        binder[0] ^= 1
    }
    if fault == "signature" {
        report[192] ^= 1
    }
    let pek = hexData(Deployment.trustedPEK)
    var measure = hexData(Deployment.trustedMeasurement)
    if fault == "measure" {
        measure[0] ^= 1
    }
    let verified = h.suffix(64) == binder && report
        .withUnsafeBytes { r in
            binder.withUnsafeBytes { b in
                pek.withUnsafeBytes { p in
                    measure.withUnsafeBytes { m in
                        verifyFn(
                            r.baseAddress,
                            b.baseAddress,
                            p.baseAddress,
                            m.baseAddress
                        ) == 1
                    }
                }
            }
        }
    return writeAll(Data([0x43, 0x53, 0x56, 0x31, 0, 5, 0, 3, 0, 0, 0, verified ? 1 : 0]) + nonce +
        lookup) && verified
}

class FilterDataProvider: NEFilterDataProvider {
    let lock = NSLock()
    var states: [UUID: FlowState] = [:]
    let log = Logger(subsystem: "com.qi.tcpra.local", category: "filter")

    var observe = false
    var observeEpoch = "unlabeled"
    let observeLock = NSLock()
    var observeFile: FileHandle?
    func event(_ flow: NEFilterFlow, _ message: String) {
        log
            .notice(
                "TCPRA \(flow.identifier.uuidString, privacy: .public) \(DispatchTime.now().uptimeNanoseconds) \(message, privacy: .public)"
            )
    }

    func observeRecord(_ flow: NEFilterFlow, _ s: FlowState, _ why: String) {
        guard observe else {
            return
        }
        s.condition.lock()
        let already = s.recorded
        s.recorded = true
        s.condition.unlock()
        guard !already else {
            return
        }
        let line = "\(observeEpoch),\(flow.identifier.uuidString),\(s.tCh),\(s.tSh),\(DispatchTime.now().uptimeNanoseconds),\(UInt64(Date().timeIntervalSince1970 * 1e9)),\(hexOut(s.lookup)),\(hexOut(s.binder))\n"
        observeLock.lock()
        if let f = observeFile {
            f.seekToEndOfFile()
            f.write(line.data(using: .utf8)!)
        }
        observeLock.unlock()
        event(flow, "OBS_RECORD \(why) ch=\(s.lookup != nil) sh=\(s.binder != nil)")
    }

    func state(_ flow: NEFilterFlow) -> FlowState? {
        lock.lock()
        defer {
            lock.unlock()
        }
        return states[flow.identifier]
    }

    func finish(_ flow: NEFilterFlow, _ state: FlowState, _ verified: Bool) {
        state.condition.lock()
        guard state.decision == nil else {
            state.condition.unlock()
            return
        }
        state.decision = verified
        let paused = state.paused
        state.condition.broadcast()
        state.condition.unlock()
        event(flow, "DECISION verified=\(verified) paused=\(paused)")
        if paused {
            resumeFlow(
                flow,
                with: verified ? NEFilterDataVerdict.allow() : NEFilterDataVerdict.drop()
            )
            event(flow, "OUT_RESUME verified=\(verified)")
        }
    }

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        if let vendor = filterConfiguration.vendorConfiguration {
            observe = (vendor["observe"] as? String) == "1"
            if let e = vendor["epoch"] as? String, !e.isEmpty {
                observeEpoch = e
            }
        }
        if observe {
            let path = "/var/tmp/tcpra-observe-\(observeEpoch).csv"
            let fm = FileManager.default
            if !fm.fileExists(atPath: path) {
                _ = fm.createFile(
                    atPath: path,
                    contents: "epoch,flow_id,t_ch_mono_ns,t_sh_mono_ns,t_close_mono_ns,t_wall_utc_ns,ch_key,sh_key\n"
                        .data(using: .utf8)
                )
            }
            observeFile = FileHandle(forWritingAtPath: path)
            if observeFile == nil {
                log.error("TCPRA_OBSERVE_FILE_FAIL \(path, privacy: .public)")
            }
        }
        let obsFlag = observe ? "1" : "0"
        let epochName = observeEpoch
        log
            .notice(
                "TCPRA_FILTER_STARTED observe=\(obsFlag, privacy: .public) epoch=\(epochName, privacy: .public)"
            )
        completionHandler(nil)
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socket = flow as? NEFilterSocketFlow,
              let endpoint = socket.remoteEndpoint as? NWHostEndpoint,
              endpoint.hostname == Deployment.serverIP,
              endpoint.port == String(Deployment.mainPort) else {
            return .allow()
        }
        log.notice("TCPRA_TARGET_FLOW")
        lock.lock()
        guard states.count < 8192 else {
            lock.unlock()
            return .drop()
        }
        let s = FlowState()
        states[flow.identifier] = s
        lock.unlock()
        if !observe {
            DispatchQueue.global().asyncAfter(deadline: .now() + 5) {
                self.finish(flow, s, false)
            }
        }
        let verdict = NEFilterNewFlowVerdict.filterDataVerdict(
            withFilterInbound: true,
            peekInboundBytes: 4096,
            filterOutbound: true,
            peekOutboundBytes: 4096
        )
        verdict.shouldReport = true
        return verdict
    }

    override func handleOutboundData(
        from flow: NEFilterFlow,
        readBytesStartOffset offset: Int,
        readBytes: Data
    ) -> NEFilterDataVerdict {
        guard let s = state(flow) else {
            return .drop()
        }
        s.condition.lock()
        defer {
            s.condition.unlock()
        }
        event(flow, "OUT_DATA offset=\(offset) bytes=\(readBytes.count)")
        if observe {
            if s.lookup != nil {
                return .allow()
            }
            guard readBytes.count >= 5
            else {
                return NEFilterDataVerdict(passBytes: 0, peekBytes: 5)
            }
            let size = 5 + Int(readBytes[3]) * 256 + Int(readBytes[4])
            guard size <= 18437, readBytes[0] == 22 else {
                event(flow, "OBS_CH_PARSE_FAIL")
                return .allow()
            }
            guard readBytes.count >= size else {
                return NEFilterDataVerdict(
                    passBytes: 0,
                    peekBytes: size
                )
            }
            guard let k = key(Data(readBytes.prefix(size)), true) else {
                event(
                    flow,
                    "OBS_CH_PARSE_FAIL"
                )
                return .allow()
            }
            s.lookup = k
            s.tCh = DispatchTime.now().uptimeNanoseconds
            event(flow, "OBS_CH bytes=\(size)")
            return .allow()
        }
        if let decision = s.decision {
            return decision ? .allow() : .drop()
        }
        if s.lookup == nil {
            guard readBytes.count >= 5
            else {
                return NEFilterDataVerdict(passBytes: 0, peekBytes: 5)
            }
            let size = 5 + Int(readBytes[3]) * 256 + Int(readBytes[4])
            guard size <= 18437, readBytes[0] == 22 else {
                return .drop()
            }
            guard readBytes.count >= size else {
                return NEFilterDataVerdict(
                    passBytes: 0,
                    peekBytes: size
                )
            }
            guard let lookup = key(Data(readBytes.prefix(size)), true) else {
                return .drop()
            }
            s.lookup = lookup
            event(flow, "CH_PASS bytes=\(size) EARLY_DISPATCH")
            let fault = filterConfiguration.vendorConfiguration?["fault"] as? String ?? "none"
            DispatchQueue.global().async {
                let verified = exchange(lookup, s, fault) {
                    self.event(flow, $0)
                }
                self.finish(flow, s, verified)
            }
            return NEFilterDataVerdict(passBytes: size, peekBytes: 4096)
        }

        if readBytes.first == 20 {
            if readBytes.count < 6 {
                return NEFilterDataVerdict(passBytes: 0, peekBytes: 6)
            }
            guard Array(readBytes.prefix(6)) == [20, 3, 3, 0, 1, 1] else {
                return .drop()
            }
            if readBytes.count == 6 {
                return NEFilterDataVerdict(passBytes: 6, peekBytes: 4096)
            }
        }
        s.paused = true
        event(flow, "OUT_HOLD bytes=\(readBytes.count)")
        return .pause()
    }

    override func handleInboundData(
        from flow: NEFilterFlow,
        readBytesStartOffset offset: Int,
        readBytes: Data
    ) -> NEFilterDataVerdict {
        guard let s = state(flow) else {
            return .drop()
        }
        s.condition.lock()
        defer {
            s.condition.unlock()
        }
        event(flow, "IN_DATA offset=\(offset) bytes=\(readBytes.count)")
        if observe {
            if s.binder != nil {
                return .allow()
            }
            guard readBytes.count >= 5
            else {
                return NEFilterDataVerdict(passBytes: 0, peekBytes: 5)
            }
            let size = 5 + Int(readBytes[3]) * 256 + Int(readBytes[4])
            guard size <= 18437, readBytes[0] == 22 else {
                event(flow, "OBS_SH_PARSE_FAIL")
                return .allow()
            }
            guard readBytes.count >= size else {
                return NEFilterDataVerdict(
                    passBytes: 0,
                    peekBytes: size
                )
            }
            guard let k = key(Data(readBytes.prefix(size)), false) else {
                event(
                    flow,
                    "OBS_SH_PARSE_FAIL"
                )
                return .allow()
            }
            s.binder = k
            s.tSh = DispatchTime.now().uptimeNanoseconds
            event(flow, "OBS_SH bytes=\(size)")
            return .allow()
        }
        if s.decision == false {
            return .drop()
        }
        guard readBytes.count >= 5 else {
            return NEFilterDataVerdict(passBytes: 0, peekBytes: 5)
        }
        let size = 5 + Int(readBytes[3]) * 256 + Int(readBytes[4])
        guard size <= 18437, readBytes[0] == 22 else {
            return .drop()
        }
        guard readBytes.count >= size else {
            return NEFilterDataVerdict(
                passBytes: 0,
                peekBytes: size
            )
        }
        guard let binder = key(Data(readBytes.prefix(size)), false) else {
            return .drop()
        }
        s.binder = binder
        s.condition.broadcast()
        event(flow, "SH_PASS bytes=\(readBytes.count)")
        return .allow()
    }

    func complete(_ flow: NEFilterFlow, inbound: Bool) -> NEFilterDataVerdict {
        guard let s = state(flow) else {
            return .drop()
        }
        s.condition.lock()
        if inbound {
            s.inboundDone = true
        } else {
            s.outboundDone = true
        }
        let closed = s.inboundDone && s.outboundDone
        let allowed = s.decision == true
        s.condition.unlock()
        if closed {
            if observe {
                observeRecord(flow, s, "complete")
            }
            lock.lock()
            states.removeValue(forKey: flow.identifier)
            lock.unlock()
        }
        if observe {
            return .allow()
        }
        return allowed ? .allow() : .drop()
    }

    override func handleInboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        complete(flow, inbound: true)
    }

    override func handleOutboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        complete(flow, inbound: false)
    }

    override func handle(_ report: NEFilterReport) {
        guard report.event == .flowClosed, let flow = report.flow else {
            return
        }
        lock.lock()
        let s = states.removeValue(forKey: flow.identifier)
        lock.unlock()
        if let s = s {
            s.condition.lock()
            if s.decision == nil {
                s.decision = false
            }
            s.condition.broadcast()
            s.condition.unlock()
            if observe {
                observeRecord(flow, s, "closed")
            }
            event(flow, "FLOW_CLOSED")
        }
    }
}

NEProvider.startSystemExtensionMode()
dispatchMain()
