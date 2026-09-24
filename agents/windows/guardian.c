#include "guardian_runtime.h"
#include "guardian.h"
enum { G_HOLD = 1, G_RELEASE = 2, G_TRIP = 3, G_DONE = 4 };
typedef struct {
    uint32_t operation, reserved;
    uint64_t handle;
} Message;
typedef struct {
    uint64_t worker_handle;
    HANDLE handle;
} Reference;
int guard_parent(const char *ip, unsigned short port, const char *output) {
    if (!run_helper(false, ip, port)) {
        fprintf(stderr, "Guardian preflight failed: firewall disabled/restricted, or endpoint "
                        "already quarantined\n");
        return 2;
    }
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE rx = NULL, child_tx = NULL, child_rx = NULL, tx = NULL;
    if (!CreatePipe(&rx, &child_tx, &sa, 0) || !CreatePipe(&child_rx, &tx, &sa, 0))
        return 2;
    SetHandleInformation(rx, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(tx, HANDLE_FLAG_INHERIT, 0);
    char worker_path[MAX_PATH];
    if (!sibling(worker_path, sizeof(worker_path), "tcpra_worker.exe"))
        return 2;
    const char *original = GetCommandLineA();

    if (*original == '"') {
        original++;
        while (*original && *original != '"')
            original++;
        if (*original)
            original++;
    } else
        while (*original && *original != ' ' && *original != '\t')
            original++;
    size_t capacity = strlen(original) + strlen(worker_path) + 180;
    char *line = (char *)malloc(capacity);
    if (!line)
        return 2;
    sprintf_s(line, capacity, "\"%s\" %s --guard-rx %llu --guard-tx %llu", worker_path, original,
              (unsigned long long)(uintptr_t)child_rx, (unsigned long long)(uintptr_t)child_tx);
    STARTUPINFOA start = {0};
    PROCESS_INFORMATION child = {0};
    start.cb = sizeof(start);
    start.dwFlags = STARTF_USESTDHANDLES;
    start.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    start.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    start.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    BOOL spawned =
        CreateProcessA(worker_path, line, NULL, NULL, TRUE, 0, NULL, NULL, &start, &child);
    free(line);
    CloseHandle(child_rx);
    CloseHandle(child_tx);
    if (!spawned) {
        CloseHandle(rx);
        CloseHandle(tx);
        return 2;
    }
    Reference refs[8192] = {0};
    size_t held = 0;
    bool clean = false, banned = false;
    PROCESS_MEMORY_COUNTERS_EX worker_memory = {0};
    worker_memory.cb = sizeof(worker_memory);
    Message message;
    while (io(rx, &message, sizeof(message), false)) {
        uint32_t ack = 0;
        if (message.operation == G_HOLD && !banned && held < 8192) {
            size_t slot = 0;
            while (slot < 8192 && refs[slot].handle)
                slot++;
            HANDLE copy = NULL;
            if (slot < 8192 &&
                DuplicateHandle(child.hProcess, (HANDLE)(uintptr_t)message.handle,
                                GetCurrentProcess(), &copy, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                refs[slot].worker_handle = message.handle;
                refs[slot].handle = copy;
                held++;
                ack = 1;
            }
        } else if (message.operation == G_RELEASE) {
            for (size_t i = 0; i < 8192; i++)
                if (refs[i].handle && refs[i].worker_handle == message.handle) {
                    CloseHandle(refs[i].handle);
                    refs[i].handle = NULL;
                    held--;
                    ack = 1;
                    break;
                }
        } else if (message.operation == G_TRIP) {
            if (!banned)
                quarantine(ip, port);
            banned = true;
            ack = 1;
        } else if (message.operation == G_DONE && held == 0 && !banned) {
            GetProcessMemoryInfo(child.hProcess, (PROCESS_MEMORY_COUNTERS *)&worker_memory,
                                 sizeof(worker_memory));
            clean = true;
            ack = 1;
        }
        if (!io(tx, &ack, sizeof(ack), true) || clean)
            break;
    }
    if (!clean && !banned) {
        quarantine(ip, port);
        banned = true;
    }
    for (size_t i = 0; i < 8192; i++)
        if (refs[i].handle)
            CloseHandle(refs[i].handle);
    CloseHandle(rx);
    CloseHandle(tx);
    WaitForSingleObject(child.hProcess, INFINITE);
    DWORD result = 3;
    GetExitCodeProcess(child.hProcess, &result);
    FILETIME created, exited, kernel, user;
    ULARGE_INTEGER wk = {0}, wu = {0}, pk = {0}, pu = {0};
    GetProcessTimes(child.hProcess, &created, &exited, &kernel, &user);
    wk.LowPart = kernel.dwLowDateTime;
    wk.HighPart = kernel.dwHighDateTime;
    wu.LowPart = user.dwLowDateTime;
    wu.HighPart = user.dwHighDateTime;
    GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user);
    pk.LowPart = kernel.dwLowDateTime;
    pk.HighPart = kernel.dwHighDateTime;
    pu.LowPart = user.dwLowDateTime;
    pu.HighPart = user.dwHighDateTime;
    PROCESS_MEMORY_COUNTERS_EX parent_memory = {0};
    parent_memory.cb = sizeof(parent_memory);
    GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&parent_memory,
                         sizeof(parent_memory));
    char metrics_path[32768];
    sprintf_s(metrics_path, sizeof(metrics_path), "%s.guardian.json", output);
    FILE *metrics = NULL;
    if (!fopen_s(&metrics, metrics_path, "w")) {
        fprintf(metrics,
                "{\"schema\":\"guardian-worker-light-v2\",\"worker_cpu_s\":%.9f,\"guardian_cpu_s\":"
                "%.9f,\"total_cpu_s\":%.9f,\"helper_cpu_s\":%.9f,\"helper_peak_ws_bytes\":%llu,"
                "\"helper_private_bytes\":%llu,\"worker_peak_ws_bytes\":%llu,\"guardian_peak_ws_"
                "bytes\":%llu,\"worker_private_bytes_at_done\":%llu,\"guardian_private_bytes_at_"
                "done\":%llu,\"clean\":%s}\n",
                (wk.QuadPart + wu.QuadPart) / 1e7, (pk.QuadPart + pu.QuadPart) / 1e7,
                (wk.QuadPart + wu.QuadPart + pk.QuadPart + pu.QuadPart) / 1e7 +
                    helper_metrics.cpu_s,
                helper_metrics.cpu_s, (unsigned long long)helper_metrics.peak_ws_bytes,
                (unsigned long long)helper_metrics.private_bytes,
                (unsigned long long)worker_memory.PeakWorkingSetSize,
                (unsigned long long)parent_memory.PeakWorkingSetSize,
                (unsigned long long)worker_memory.PrivateUsage,
                (unsigned long long)parent_memory.PrivateUsage, clean ? "true" : "false");
        fclose(metrics);
    }
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    return clean ? (int)result : 3;
}

int main(int argc, char **argv) {
    const char *ip = NULL, *output = NULL;
    unsigned short port = 19443;
    for (int i = 1; i + 1 < argc; i++) {
        if (!strcmp(argv[i], "--server-ip"))
            ip = argv[i + 1];
        if (!strcmp(argv[i], "--output"))
            output = argv[i + 1];
        if (!strcmp(argv[i], "--main-port")) {
            char *end = NULL;
            unsigned long n = strtoul(argv[i + 1], &end, 10);
            if (!n || n > 65535 || *end)
                return 2;
            port = (unsigned short)n;
        }
    }
    if (!ip || !output) {
        fprintf(stderr, "Use --server-ip IP --output CSV with normal agent options\n");
        return 2;
    }
    return guard_parent(ip, port, output);
}
