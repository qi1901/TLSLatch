#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <psapi.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct {
    double cpu_s;
    uint64_t peak_ws_bytes, private_bytes;
} HelperMetrics;
static bool io(HANDLE h, void *buffer, DWORD length, bool write) {
    DWORD done = 0, part;
    while (done < length) {
        BOOL ok = write ? WriteFile(h, (char *)buffer + done, length - done, &part, NULL)
                        : ReadFile(h, (char *)buffer + done, length - done, &part, NULL);
        if (!ok || !part)
            return false;
        done += part;
    }
    return true;
}

#ifndef FIREWALL_HELPER
static HelperMetrics helper_metrics;
static bool sibling(char *path, size_t size, const char *name) {
    DWORD n = GetModuleFileNameA(NULL, path, (DWORD)size);
    if (!n || n >= size)
        return false;
    char *slash = strrchr(path, '\\');
    return slash && strcpy_s(slash + 1, size - (size_t)(slash + 1 - path), name) == 0;
}

static bool run_helper(bool install, const char *ip, unsigned short port) {
    char path[MAX_PATH], line[1024];
    if (!sibling(path, sizeof(path), "tcpra_firewall.exe"))
        return false;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE rx = NULL, tx = NULL;
    if (!CreatePipe(&rx, &tx, &sa, 0))
        return false;
    SetHandleInformation(rx, HANDLE_FLAG_INHERIT, 0);
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &bytes);
    STARTUPINFOEXA start = {0};
    PROCESS_INFORMATION child = {0};
    start.StartupInfo.cb = sizeof(start);
    start.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(bytes);
    bool initialized = false, ok = false;
    if (!start.lpAttributeList)
        goto done;
    if (!InitializeProcThreadAttributeList(start.lpAttributeList, 1, 0, &bytes))
        goto done;
    initialized = true;
    if (!UpdateProcThreadAttribute(start.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &tx,
                                   sizeof(tx), NULL, NULL))
        goto done;
    sprintf_s(line, sizeof(line), "\"%s\" %s %s %u %llu", path, install ? "block" : "check", ip,
              port, (unsigned long long)(uintptr_t)tx);
    if (!CreateProcessA(path, line, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
                        &start.StartupInfo, &child))
        goto done;
    CloseHandle(tx);
    tx = NULL;
    HelperMetrics measured = {0};
    bool measured_ok = io(rx, &measured, sizeof(measured), false);
    WaitForSingleObject(child.hProcess, INFINITE);
    DWORD result = 2;
    GetExitCodeProcess(child.hProcess, &result);
    FILETIME c, e, k, u;
    ULARGE_INTEGER kt, ut;
    if (GetProcessTimes(child.hProcess, &c, &e, &k, &u)) {
        kt.LowPart = k.dwLowDateTime;
        kt.HighPart = k.dwHighDateTime;
        ut.LowPart = u.dwLowDateTime;
        ut.HighPart = u.dwHighDateTime;
        measured.cpu_s = (kt.QuadPart + ut.QuadPart) / 1e7;
    }
    helper_metrics.cpu_s += measured.cpu_s;
    if (measured.peak_ws_bytes > helper_metrics.peak_ws_bytes)
        helper_metrics.peak_ws_bytes = measured.peak_ws_bytes;
    if (measured.private_bytes > helper_metrics.private_bytes)
        helper_metrics.private_bytes = measured.private_bytes;
    ok = measured_ok && result == 0;
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
done:
    if (initialized)
        DeleteProcThreadAttributeList(start.lpAttributeList);
    free(start.lpAttributeList);
    if (tx)
        CloseHandle(tx);
    if (rx)
        CloseHandle(rx);
    return ok;
}
static void quarantine(const char *ip, unsigned short port) {

    while (!run_helper(true, ip, port)) {
        fprintf(stderr, "TLSLATCH_QUARANTINE_RETRY target=%s:%u\n", ip, port);
        Sleep(1000);
    }
    fprintf(stderr, "TLSLATCH_QUARANTINED target=%s:%u manual_recovery_required=true\n", ip, port);
}
#endif
