#pragma once
#include <string>
#include <fstream>
#include <filesystem>

/* 拒绝反斜杠，从你我做起 */

#ifdef _WIN32
#include <windows.h>

// Windows: UTF-8 字符串转宽字符（用于打开文件）
inline std::wstring utf8_to_windows_path(const std::string& utf8_path) {
    if (utf8_path.empty()) return L"";

    int len = MultiByteToWideChar(CP_UTF8, 0, utf8_path.c_str(), -1, nullptr, 0);
    std::wstring wide_path(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8_path.c_str(), -1, wide_path.data(), len);
    wide_path.pop_back();  // 移除末尾的 null
    return wide_path;
}

// 跨平台打开 ofstream（接受 UTF-8 路径）
inline std::ofstream open_ofstream(const std::string& utf8_path, std::ios::openmode mode = std::ios::out) {
    std::wstring wide_path = utf8_to_windows_path(utf8_path);
    return std::ofstream(wide_path, mode);
}

// 跨平台打开 ifstream（接受 UTF-8 路径）
inline std::ifstream open_ifstream(const std::string& utf8_path, std::ios::openmode mode = std::ios::in) {
    std::wstring wide_path = utf8_to_windows_path(utf8_path);
    return std::ifstream(wide_path, mode);
}

// 检查文件是否存在
inline bool file_exists(const std::string& utf8_path) {
    std::wstring wide_path = utf8_to_windows_path(utf8_path);
    DWORD attrs = GetFileAttributesW(wide_path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

#else
// Linux/macOS: 直接使用 UTF-8

inline std::ofstream open_ofstream(const std::string& utf8_path, std::ios::openmode mode = std::ios::out) {
    return std::ofstream(utf8_path, mode);
}

inline std::ifstream open_ifstream(const std::string& utf8_path, std::ios::openmode mode = std::ios::in) {
    return std::ifstream(utf8_path, mode);
}

inline bool file_exists(const std::string& utf8_path) {
    return std::filesystem::exists(utf8_path);
}

#endif