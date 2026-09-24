#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <netfw.h>
#include <iphlpapi.h>
#include <oleauto.h>
#define FIREWALL_HELPER
#include "guardian_runtime.h"

static bool firewall(bool install, const char *ip, unsigned short port) {
    HRESULT init = CoInitializeEx(NULL, COINIT_MULTITHREADED), hr;
    INetFwPolicy2 *policy = NULL;
    INetFwRules *rules = NULL;
    INetFwRule *rule = NULL;
    wchar_t address[64], name[128], ports[16];
    MultiByteToWideChar(CP_UTF8, 0, ip, -1, address, 64);
    swprintf_s(name, 128, L"TLSLatch-Quarantine-%s-%u", address, port);
    swprintf_s(ports, 16, L"%u", port);
    BSTR bname = SysAllocString(name), bip = SysAllocString(address), bport = SysAllocString(ports);
    bool ok = false;
    if (FAILED(init) && init != RPC_E_CHANGED_MODE)
        goto done;
    if (!bname || !bip || !bport)
        goto done;
    hr = CoCreateInstance(&CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER, &IID_INetFwPolicy2,
                          (void **)&policy);
    if (FAILED(hr))
        goto done;
    long profiles = 0;
    if (FAILED(INetFwPolicy2_get_CurrentProfileTypes(policy, &profiles)))
        goto done;
    for (long flag = 1; flag <= 4; flag <<= 1) {
        VARIANT_BOOL enabled = VARIANT_FALSE;
        if ((profiles & flag) && (FAILED(INetFwPolicy2_get_FirewallEnabled(
                                      policy, (NET_FW_PROFILE_TYPE2)flag, &enabled)) ||
                                  enabled != VARIANT_TRUE))
            goto done;
    }
    NET_FW_MODIFY_STATE modify;
    if (FAILED(INetFwPolicy2_get_LocalPolicyModifyState(policy, &modify)) ||
        modify != NET_FW_MODIFY_STATE_OK)
        goto done;
    if (FAILED(INetFwPolicy2_get_Rules(policy, &rules)))
        goto done;
    hr = INetFwRules_Item(rules, bname, &rule);
    if (!install) {
        ok = FAILED(hr);
        goto done;
    }
    if (SUCCEEDED(hr)) {
        INetFwRule_Release(rule);
        rule = NULL;
    }
    if (FAILED(CoCreateInstance(&CLSID_NetFwRule, NULL, CLSCTX_INPROC_SERVER, &IID_INetFwRule,
                                (void **)&rule)))
        goto done;
#define SET(call)                                                                                  \
    do {                                                                                           \
        if (FAILED(call))                                                                          \
            goto done;                                                                             \
    } while (0)
    SET(INetFwRule_put_Name(rule, bname));
    SET(INetFwRule_put_Protocol(rule, IPPROTO_TCP));
    SET(INetFwRule_put_RemoteAddresses(rule, bip));
    SET(INetFwRule_put_RemotePorts(rule, bport));
    SET(INetFwRule_put_Direction(rule, NET_FW_RULE_DIR_OUT));
    SET(INetFwRule_put_Action(rule, NET_FW_ACTION_BLOCK));
    SET(INetFwRule_put_Profiles(rule, NET_FW_PROFILE2_ALL));
    SET(INetFwRule_put_Enabled(rule, VARIANT_TRUE));
    SET(INetFwRules_Add(rules, rule));
#undef SET
    ok = true;
done:
    if (rule)
        INetFwRule_Release(rule);
    if (rules)
        INetFwRules_Release(rules);
    if (policy)
        INetFwPolicy2_Release(policy);
    SysFreeString(bname);
    SysFreeString(bip);
    SysFreeString(bport);
    if (SUCCEEDED(init))
        CoUninitialize();
    return ok;
}

static bool abort_connections(const char *ip, unsigned short port) {
    IN_ADDR address;
    if (InetPtonA(AF_INET, ip, &address) != 1)
        return false;
    DWORD size = 0;
    GetTcpTable(NULL, &size, FALSE);
    for (int retry = 0; retry < 4; retry++) {
        MIB_TCPTABLE *table = (MIB_TCPTABLE *)malloc(size);
        if (!table)
            return false;
        DWORD error = GetTcpTable(table, &size, FALSE);
        if (error == ERROR_INSUFFICIENT_BUFFER) {
            free(table);
            continue;
        }
        if (error) {
            free(table);
            return false;
        }
        bool ok = true;
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            MIB_TCPROW row = table->table[i];
            if (row.dwRemoteAddr != address.S_un.S_addr || row.dwRemotePort != htons(port))
                continue;
            if (row.dwState == MIB_TCP_STATE_TIME_WAIT || row.dwState == MIB_TCP_STATE_CLOSED)
                continue;
            row.dwState = MIB_TCP_STATE_DELETE_TCB;
            error = SetTcpEntry(&row);
            if (error && error != ERROR_NOT_FOUND)
                ok = false;
        }
        free(table);
        return ok;
    }
    return false;
}

int main(int argc, char **argv) {
    if (argc != 5 || (strcmp(argv[1], "check") && strcmp(argv[1], "block")))
        return 2;
    IN_ADDR addr;
    char *end = NULL;
    unsigned long port = strtoul(argv[3], &end, 10);
    if (InetPtonA(AF_INET, argv[2], &addr) != 1 || !port || port > 65535 || *end)
        return 2;
    bool install = !strcmp(argv[1], "block");
    bool ok = firewall(install, argv[2], (unsigned short)port);
    if (install && ok)
        ok = abort_connections(argv[2], (unsigned short)port);
    PROCESS_MEMORY_COUNTERS_EX mem = {0};
    mem.cb = sizeof(mem);
    HelperMetrics metrics = {0};
    if (!GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&mem, sizeof(mem)))
        ok = false;
    metrics.peak_ws_bytes = (uint64_t)mem.PeakWorkingSetSize;
    metrics.private_bytes = (uint64_t)mem.PrivateUsage;
    HANDLE tx = (HANDLE)(uintptr_t)_strtoui64(argv[4], NULL, 10);
    if (!io(tx, &metrics, sizeof(metrics), true))
        ok = false;
    CloseHandle(tx);
    return ok ? 0 : 2;
}
