#include <iostream>
#include <string>
#include <fstream>

#include "api.h"

#ifdef _WIN32
#include <windows.h>
std::wstring utf8_to_wide(const std::string& utf8_str) {
    if (utf8_str.empty()) return std::wstring();

    int len = MultiByteToWideChar(CP_UTF8, 0, utf8_str.c_str(), -1, NULL, 0);
    if (len <= 0) return std::wstring();

    std::wstring wide_str(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8_str.c_str(), -1, &wide_str[0], len);
    wide_str.pop_back();
    return wide_str;
}
#endif

bool FundamentalAnalysis::readfile(std::string filepath) {
#ifdef _WIN32 // Windows平台：使用宽字符版本
    std::wstring wpath = utf8_to_wide(filepath);
    myfile.open(wpath.c_str(), std::ios::binary);
#else         // Linux/Mac平台：直接使用UTF-8路径
    myfile.open(file_path.c_str(), std::ios::binary);
#endif
    if (!myfile.is_open()) {
        return false;
    }
    else {
        myfile.seekg(0, std::ios::end);
        file_size = myfile.tellg();
        myfile.seekg(0, std::ios::beg);
        return true;
    }
}

bool FundamentalAnalysis::check_little_endian() {
    uint32_t test = 0x12345678;
    if (*(uint8_t*)&test != 0x78) {
		return false; // 非小端序
    }
	return true;      // 小端序
}

FundamentalAnalysis::error_code FundamentalAnalysis::analysis_file(const std::string input_filepath) {
    if (!check_little_endian()) {
        return error_code::PLATFORM_NOT_SUPPORTED;
	}

    if (readfile(input_filepath)) {
        PEanalyzer target(myfile);
        target.dosheader_analysis(data_container);
        target.dosstub_analysis(data_container);
        target.file_header_analysis(data_container);
        target.optional_header_analysis(data_container);
		target.section_headers_analysis(data_container);

        return error_code::SUCCESS;
    }
    else {
        std::ifstream test(input_filepath);
        if (!test.good()) {
            return error_code::FILE_NOT_FOUND;
        }
        test.close();
        return error_code::FILE_ACCESS_DENIED;
    }
}