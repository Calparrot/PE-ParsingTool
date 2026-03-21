#ifndef TRANSLATOR_H
#define TRANSLATOR_H

#include <iomanip>
#include <string>
#include <sstream>
#include <cstdint>

#include "database.h"

/*
    struct_to_hexstring()  ：将任意结构体转换为16进制字符串
    byte_to_ascii()        ：将字节值转换为ASCII字符（不可见字符替换为点）
    generate_file_display()：源文件信息整理
*/

template<typename T>
std::wstring struct_to_hexstring(const T& data) {
    if constexpr (std::is_empty_v<T>) {
        return L"<empty struct>";
    }

    std::wstringstream wss;
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&data);

    for (size_t i = 0; i < sizeof(T); i++) {
        wss << std::hex << std::setw(2) << std::setfill(L'0')
            << static_cast<int>(bytes[i]);
    }

    return wss.str();
}

std::wstring vector_to_hexstring(const std::vector<uint8_t>& data);
std::wstring hexstring_to_ascii(const std::wstring& hexstring);
std::wstring generate_file_display(structuresults data_container);

#endif // !TRANSLATOR_H