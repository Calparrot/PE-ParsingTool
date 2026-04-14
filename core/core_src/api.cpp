#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>

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

/* 由界面翻译转API翻译的 过渡期代码 */
/* private */
std::string Translator::vector_to_hexstring(const std::vector<uint8_t>& input_data) {
    std::stringstream ss;
    ss << std::hex << std::uppercase;
    for (uint8_t byte : input_data) {
        ss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(byte);
    }
    return ss.str();
}

std::string Translator::hexstring_to_ascii(const std::string& hexstring) {
    std::string ascii;

    for (size_t i = 0; i < hexstring.length(); i += 2) {
        if (i + 1 >= hexstring.length()) break;

        std::string byteStr = hexstring.substr(i, 2);
        char* endPtr;
        int byte_val = std::strtol(byteStr.c_str(), &endPtr, 16);

        if (byte_val >= 32 && byte_val <= 126) {
            ascii += static_cast<char>(byte_val);
        }
        else {
            ascii += '.';
        }
    }

    return ascii;
}

std::string Translator::generate_file_display(const std::vector<uint8_t>& input_data) {
    std::string hexadecimal_view;
    std::string raw_data;
    std::string ascii;
    std::stringstream ss;
    int temporary_address = 0;
    size_t j = 0;

    raw_data.append(vector_to_hexstring(input_data));
    size_t num = raw_data.length();

    ascii = hexstring_to_ascii(raw_data);

    for (size_t i = 0; i < num; i++) {
        if (i % 32 == 0) {
            ss.str("");
            ss.clear();
            ss << std::hex << std::uppercase;
            ss << std::hex << std::setw(8) << std::setfill('0') << temporary_address;
            hexadecimal_view.append(ss.str());
            hexadecimal_view.append("    ");
            temporary_address += 16;
        }

        hexadecimal_view += (raw_data[i]);
        if ((i + 1) % 2 == 0) {
            hexadecimal_view += " ";
        }
        if (i % 32 == 31) {
            hexadecimal_view += "   ";
            hexadecimal_view.append(ascii, (i + 1) / 2 - 16, 16);
            hexadecimal_view += "\r\n";
        }
    }

    if ((num - 1) % 32 != 31) {
        size_t temp = 31 - ((num - 1) % 32);
        temp += (temp / 2 + 3);
        hexadecimal_view.append(temp, ' ');
    }

    return hexadecimal_view;
}

bool Translator::string_to_file_append(const std::wstring& export_filepath, const std::string& input_data) {
    std::ofstream output_file(export_filepath, std::ios::app | std::ios::binary); // 追加写入而不是覆盖
    if (!output_file.is_open()) {
        return false;
    }

    output_file << input_data;
    output_file.close();
    return true;
}
/* public */
bool Translator::hexadecimal_document_export(const std::wstring& export_filepath) {
	unsigned int file_size = data_container.source_file_data.size();
	unsigned int offset = 0;
	unsigned int chunk_size = 1024; 
    std::vector<uint8_t> current_data;

    while (offset < file_size) {
        unsigned int current_size = (chunk_size <= file_size - offset) ? chunk_size : file_size - offset;
        current_data.assign(
            data_container.source_file_data.begin() + offset,
            data_container.source_file_data.begin() + offset + current_size
        );

        if (!string_to_file_append(export_filepath, generate_file_display(current_data))) {
            return false;
        }

        offset += chunk_size;
    }
    return true;
}
/* 过渡代码结束 */

bool FundamentalAnalysis::readfile(std::string file_path) {
#ifdef _WIN32 // Windows平台：使用宽字符版本
    std::wstring wpath = utf8_to_wide(file_path);
    myfile.open(wpath.c_str(), std::ios::binary);
#else         // Linux/Mac平台：直接使用UTF-8路径
    myfile.open(file_path.c_str(), std::ios::binary);
#endif
    if (!myfile.is_open()) {
        return false;
    }
    myfile.seekg(0, std::ios::end);
    file_size = myfile.tellg();
    myfile.seekg(0, std::ios::beg);

    data_manager.data_container.source_file_data.resize(file_size);
    myfile.read(reinterpret_cast<char*>(data_manager.data_container.source_file_data.data()), file_size);

    return true;
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

    bool previous_execution_result = readfile(input_filepath);
    uint8_t execution_steps = 0;
    PEanalyzer target(myfile);

    if (previous_execution_result) {
        previous_execution_result = target.dosheader_analysis(data_manager.data_container);
        execution_steps++;
    }
    if (previous_execution_result) {
        previous_execution_result = target.dosstub_analysis(data_manager.data_container);
        execution_steps++;
    }
    if (previous_execution_result) {
        previous_execution_result = target.file_header_analysis(data_manager.data_container);
        execution_steps++;
    }
    if (previous_execution_result) {
        previous_execution_result = target.optional_header_analysis(data_manager.data_container);
        execution_steps++;
    }
    if (previous_execution_result) {
        previous_execution_result = target.section_headers_analysis(data_manager.data_container);
        execution_steps++;
    }

    if (previous_execution_result) {
        return error_code::SUCCESS;
    }
    else {
        std::ifstream test(input_filepath);
        switch (execution_steps) {
        case 0:
            if (!test.good()) {
                return error_code::FILE_NOT_FOUND;
            }
            test.close();
            return error_code::FILE_ACCESS_DENIED;
        default:
            data_manager.data_container.output_range = execution_steps;
            return error_code::SUCCESS;
        }
    }
}