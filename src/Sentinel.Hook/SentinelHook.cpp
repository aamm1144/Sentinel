// SentinelHook.dll — Winsock connect() hook for Sentinel proxy redirection.
// Compiled as a 32-bit (x86) DLL. Injected into Conquer.exe at startup.
//
// Uses MinHook for inline hooking of ws2_32.dll!connect().
// When a connection targets a known game-server IP, the destination is
// rewritten to 127.0.0.1 so traffic flows through the Sentinel proxy.

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

#include "MinHook.h"

#pragma comment(lib, "ws2_32.lib")

// ---------------------------------------------------------------------------
// Configuration — IPs to redirect
// ---------------------------------------------------------------------------

struct RedirectEntry {
    ULONG originalIp;
    const char* label;
};

static RedirectEntry g_redirects[] = {
    { 0, "51.75.116.175"  },
    { 0, "51.75.241.136" },
};

static const int g_redirectCount = sizeof(g_redirects) / sizeof(g_redirects[0]);
static ULONG g_loopback = 0; // 127.0.0.1

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

static FILE* g_logFile = nullptr;

static void LogInit()
{
    g_logFile = fopen("SentinelHook.log", "a");
    if (g_logFile) {
        fprintf(g_logFile, "\n--- SentinelHook loaded (PID %lu) ---\n", GetCurrentProcessId());
        fflush(g_logFile);
    }
}

static void Log(const char* fmt, ...)
{
    if (!g_logFile) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(g_logFile, fmt, args);
    va_end(args);
    fflush(g_logFile);
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

typedef int (WINAPI* connect_t)(SOCKET s, const struct sockaddr* name, int namelen);
static connect_t g_originalConnect = nullptr;

static int WINAPI HookedConnect(SOCKET s, const struct sockaddr* name, int namelen)
{
    if (name && namelen >= sizeof(struct sockaddr_in))
    {
        struct sockaddr_in* addr = (struct sockaddr_in*)name;

        if (addr->sin_family == AF_INET)
        {
            ULONG ip = addr->sin_addr.S_un.S_addr;
            USHORT port = ntohs(addr->sin_port);

            for (int i = 0; i < g_redirectCount; ++i)
            {
                if (ip == g_redirects[i].originalIp)
                {
                    Log("[REDIRECT] %s:%u -> 127.0.0.1:%u\n",
                        g_redirects[i].label, port, port);

                    addr->sin_addr.S_un.S_addr = g_loopback;
                    break;
                }
            }
        }
    }

    return g_originalConnect(s, name, namelen);
}

// ---------------------------------------------------------------------------
// Hook installation / removal
// ---------------------------------------------------------------------------

static bool InstallHook()
{
    if (MH_Initialize() != MH_OK)
        return false;

    // Resolve connect from ws2_32.dll
    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    if (!hWs2)
        hWs2 = LoadLibraryA("ws2_32.dll");
    if (!hWs2)
        return false;

    void* pConnect = GetProcAddress(hWs2, "connect");
    if (!pConnect)
        return false;

    if (MH_CreateHook(pConnect, &HookedConnect,
                       reinterpret_cast<LPVOID*>(&g_originalConnect)) != MH_OK)
        return false;

    if (MH_EnableHook(pConnect) != MH_OK)
        return false;

    return true;
}

static void RemoveHook()
{
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}

// ---------------------------------------------------------------------------
// DLL entry point
// ---------------------------------------------------------------------------

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        // Resolve IPs once
        g_loopback = inet_addr("127.0.0.1");
        for (int i = 0; i < g_redirectCount; ++i)
            g_redirects[i].originalIp = inet_addr(g_redirects[i].label);

        LogInit();

        if (InstallHook())
            Log("[HOOK] connect() hooked successfully\n");
        else
            Log("[HOOK] FAILED to hook connect()\n");
        break;

    case DLL_PROCESS_DETACH:
        RemoveHook();
        Log("[HOOK] unloaded\n");
        if (g_logFile) { fclose(g_logFile); g_logFile = nullptr; }
        break;
    }

    return TRUE;
}
