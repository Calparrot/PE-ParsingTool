#include <Windows.h>
#include <string>

#include "utils.h"

std::wstring get_exe_directory() {
    wchar_t buffer[MAX_PATH];
    if (GetModuleFileNameW(NULL, buffer, MAX_PATH) == 0) {
        return L"";
    }

    std::wstring exe_path(buffer);
    size_t last_slash = exe_path.find_last_of(L"\\/");

    if (last_slash == std::wstring::npos) {
        return L"";
    }

    return exe_path.substr(0, last_slash);
}

std::string wstring_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return "";

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.length(),
        NULL, 0, NULL, NULL);
    std::string result(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.length(),
        &result[0], size_needed, NULL, NULL);
    return result;
}