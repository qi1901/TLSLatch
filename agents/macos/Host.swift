import Foundation
import SystemExtensions
import NetworkExtension

let identifier = "com.qi.tcpra.local.filter"
func emit(_ message: String) {
    print(message)
    fflush(stdout)
}

final class Manager: NSObject, OSSystemExtensionRequestDelegate {
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        emit("USER_APPROVAL_REQUIRED")
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        emit("ACTIVATION_FAILED \(error)")
        exit(1)
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        emit("ACTIVATION_FINISHED \(result.rawValue)")
        exit(0)
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }
}

let manager = Manager()
let args = Array(CommandLine.arguments.dropFirst())
let action = args.first ?? "activate"
guard ["activate", "deactivate", "enable", "disable", "remove"].contains(action) else {
    emit("Usage: TcpraLocal activate|deactivate|enable|disable|remove")
    exit(2)
}

if action == "activate" || action == "deactivate" {
    let request = action == "activate" ? OSSystemExtensionRequest.activationRequest(
        forExtensionWithIdentifier: identifier,
        queue: .main
    ) : OSSystemExtensionRequest.deactivationRequest(
        forExtensionWithIdentifier: identifier,
        queue: .main
    )
    request.delegate = manager
    OSSystemExtensionManager.shared.submitRequest(request)
} else {
    let filter = NEFilterManager.shared()
    filter.loadFromPreferences { error in
        if let error = error {
            emit("LOAD_FAILED \(error)")
            exit(1)
        }
        if action == "remove" {
            filter.removeFromPreferences { error in
                emit("REMOVE \(String(describing: error))")
                exit(error == nil ? 0 : 1)
            }
        } else {
            let config = NEFilterProviderConfiguration()
            config.filterSockets = true
            config.filterPackets = false
            config.filterDataProviderBundleIdentifier = identifier
            config.vendorConfiguration = ["fault": "none"]
            filter.providerConfiguration = config
            filter.localizedDescription = "TLSLatch network attestation"
            filter.isEnabled = action == "enable"
            filter.saveToPreferences { error in
                emit("SAVE \(String(describing: error))")
                exit(error == nil ? 0 : 1)
            }
        }
    }
}

DispatchQueue.main.asyncAfter(deadline: .now() + 45) {
    emit("TIMEOUT")
    exit(2)
}

RunLoop.main.run()
