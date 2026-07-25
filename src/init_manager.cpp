// init_manager.cpp
#include <windows.h>
#include <string>
#include <filesystem>
#include <iostream>

// Determine config file path relative to executable
std::filesystem::path get_config_path() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::filesystem::path path(exePath);
    return path.parent_path() / "config.ini";
}

// Self-healing DLL loader for x64 wintun.dll
bool load_wintun_dll() {
    // Check if wintun.dll exists in the executable directory
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::filesystem::path exeDir(exePath);
    std::filesystem::path dllPath = exeDir / "wintun.dll";

    // If file exists, attempt to load it
    if (std::filesystem::exists(dllPath)) {
        HMODULE hDll = LoadLibraryW(dllPath.string().c_str());
        if (hDll) {
            return true;
        }
    }

    // DLL missing or load failed -> download
    std::wcout << L"[INFO] Wintun DLL missing or architecture mismatch. Starting auto-download...\n";

    // InternetOpenW setup
    HINTERNET hInternet = InternetOpenW(L"BypassEngine/1.0", INTERNET_OPEN_TYPE_PRECONFIGED, nullptr, nullptr, 0);
    if (!hInternet) return false;

    // Build URL (example)
    const wchar_t* url = L"https://www.wintun.net/amd64/wintun.dll";
    HINTERNET hUrl = InternetOpenUrlW(hInternet, url, nullptr, 0, 0, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return false;
    }

    // Buffer for data
    const DWORD bufferSize = 4096;
    char buffer[bufferSize];
    DWORD bytesRead;

    // Write to file
    HANDLE hFile = CreateFileW(dllPath.string().c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        return false;
    }

    while (InternetReadFile(hUrl, buffer, bufferSize, &bytesRead) && bytesRead != 0) {
        DWORD written;
        WriteFile(hFile, buffer, bytesRead, &written, nullptr);
    }

    CloseHandle(hFile);
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    // Reload the DLL
    HMODULE hDll = LoadLibraryW(dllPath.string().c_str());
    return hDll != nullptr;
}

int main() {
    // Example usage
    auto configPath = get_config_path();
    std::wcout << L"Config path: " << configPath.wstring() << L"\n";

    if (load_wintun_dll()) {
        std::wcout << L"[INFO] Wintun DLL loaded successfully.\n";
    } else {
        std::wcerr << L"[ERROR] Failed to load Wintun DLL.\n";
    }

    return 0;
}