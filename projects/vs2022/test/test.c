#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

struct LANGANDCODEPAGE {
	WORD language;
	WORD codePage;
} *lpTranslate;

void PrintFileVersion(const char* filePath)
{
    DWORD  verHandle = 0;
    DWORD  verSize = GetFileVersionInfoSizeA(filePath, &verHandle);

    if (verSize == 0) {
        DWORD err = GetLastError();
        printf("Error %d: Cannot get version info size\n", err);
        return;
    }

    LPBYTE verData = (LPBYTE)malloc(verSize);
    if (!verData) {
        printf("Error: Memory allocation failed\n");
        return;
    }

    // 读取版本信息
    if (!GetFileVersionInfoA(filePath, verHandle, verSize, verData)) {
        free(verData);
        printf("Error %d: Cannot get version info\n", GetLastError());
        return;
    }

    // 查询语言和代码页
    VS_FIXEDFILEINFO* pFileInfo = NULL;
    UINT len = 0;
    if (!VerQueryValueA(verData, "\\", (LPVOID*)&pFileInfo, &len)) {
        free(verData);
        printf("Error: Cannot query version value\n");
        return;
    }

    // 打印基本版本信息
    printf("File: %s\n", filePath);
    printf("File Version: %d.%d.%d.%d\n",
        HIWORD(pFileInfo->dwFileVersionMS),
        LOWORD(pFileInfo->dwFileVersionMS),
        HIWORD(pFileInfo->dwFileVersionLS),
        LOWORD(pFileInfo->dwFileVersionLS));

    UINT translateLen = 0;
    if (VerQueryValueA(verData, "\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &translateLen)) {
        for (UINT i = 0; i < (translateLen / sizeof(struct LANGANDCODEPAGE)); i++) {
            char subBlock[256];

            // 获取产品名称
            sprintf_s(subBlock, sizeof(subBlock),
                "\\StringFileInfo\\%04x%04x\\ProductName",
				lpTranslate[i].language, lpTranslate[i].codePage);
            char* productName = NULL;
            if (VerQueryValueA(verData, subBlock, (LPVOID*)&productName, &len) && len > 0) {
                printf("Product: %s\n", productName);
            }

            // 获取文件描述
            sprintf_s(subBlock, sizeof(subBlock),
                "\\StringFileInfo\\%04x%04x\\FileDescription",
                lpTranslate[i].language, lpTranslate[i].codePage);
            char* fileDesc = NULL;
            if (VerQueryValueA(verData, subBlock, (LPVOID*)&fileDesc, &len) && len > 0) {
                printf("Description: %s\n", fileDesc);
            }

            // 获取公司名称
            sprintf_s(subBlock, sizeof(subBlock),
                "\\StringFileInfo\\%04x%04x\\CompanyName",
                lpTranslate[i].language, lpTranslate[i].codePage);
            char* company = NULL;
            if (VerQueryValueA(verData, subBlock, (LPVOID*)&company, &len) && len > 0) {
                printf("Company: %s\n", company);
            }
        }
    }

    free(verData);
}

int main()
{
    printf("version dll hijack test!\n");
    PrintFileVersion("cmd.exe");
	system("pause");
    return 0;
}
