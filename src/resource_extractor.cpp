#include "resource_extractor.h"
#include <windows.h>
#include <shlobj.h>
#include <fstream>
#include <filesystem>

namespace {
    bool ExtractResource(const wchar_t* resource_name, const std::wstring& output_path) {
        HMODULE hModule = GetModuleHandleW(nullptr);
        if (!hModule) return false;

        HRSRC hRes = FindResourceW(hModule, resource_name, (LPCWSTR)MAKEINTRESOURCE(RT_RCDATA));
        if (!hRes) return false;

        HGLOBAL hLoaded = LoadResource(hModule, hRes);
        if (!hLoaded) return false;

        void* pData = LockResource(hLoaded);
        DWORD size = SizeofResource(hModule, hRes);
        if (!pData || size == 0) return false;

        std::ofstream out(output_path, std::ios::binary);
        if (!out) return false;

        out.write(static_cast<const char*>(pData), size);
        out.close();

        return true;
    }

    bool FileExists(const std::wstring& path) {
        std::error_code ec;
        return std::filesystem::exists(path, ec);
    }
}

void ExtractEmbeddedDependencies() {
    wchar_t appdata_path[MAX_PATH];
    if (SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appdata_path) != S_OK) {
        return;
    }

    std::wstring extract_dir = std::wstring(appdata_path) + L"\\BypassTSPY";
    
    std::error_code ec;
    std::filesystem::create_directories(extract_dir, ec);

    std::wstring windivert_dll = extract_dir + L"\\WinDivert.dll";
    std::wstring windivert_sys = extract_dir + L"\\WinDivert64.sys";
    std::wstring wintun_dll = extract_dir + L"\\wintun.dll";

    if (!FileExists(windivert_dll)) {
        ExtractResource(L"WinDivert.dll", windivert_dll);
    }
    if (!FileExists(windivert_sys)) {
        ExtractResource(L"WinDivert64.sys", windivert_sys);
    }
    if (!FileExists(wintun_dll)) {
        ExtractResource(L"wintun.dll", wintun_dll);
    }

    SetDllDirectoryW(extract_dir.c_str());
}
