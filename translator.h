#ifndef TRANSLATOR_H
#define TRANSLATOR_H

#include <iomanip>
#include <string>
#include <sstream>
#include <cstdint>

/*
    struct_to_hexstring()   ：将任意结构体转换为16进制字符串
    vector_to_hexstring()   ：uint_8型vector转十六进制wstring类
    hexstring_to_ascii      ：十六进制wstring类转ascii码wstring类
    generate_file_display() ：源文件信息整理
    
    scan_summary()          ：扫描结果汇总
*/

/* 工具函数 */
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
std::wstring degree_judgement(Core::Severity severity);
std::wstring string_to_wstring(const std::string& str, UINT code_page = CP_UTF8);

/* 翻译函数 */
std::wstring generate_file_display(structuresults data_container);
std::wstring result_translator(Core::Diagnostic structured_results);
std::wstring scan_summary(structuresults data_container);

#endif // !TRANSLATOR_H