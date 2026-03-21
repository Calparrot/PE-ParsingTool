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

FundamentalAnalysis::error_code FundamentalAnalysis::analysis_file(const std::string input_filepath) {
    if (readfile(input_filepath)) {
        PEanalyzer target(myfile);
        target.dosheader_analysis(data_container);
        target.dosstub_analysis(data_container);
        target.file_header_analysis(data_container);
        target.optional_header_analysis(data_container);

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


/*
    filepath：目标文件路径
    myfile  ：目标文件流
    target  ：目标文件解析器（一阶段）


uint64_t file_size;
bool readfile(std::string filepath, std::ifstream& file); // 打开文件

int main() {
    std::string filepath;
    std::ifstream myfile;

    std::cout << "- 输入文件路径：";
    while (1) {
        std::cin >> filepath;
        if (readfile(filepath, myfile)) {
            break;
        }
        else {
            std::cout << "- 文件加载失败，请检查是否输入有误：";
        }
    }

    PEanalyzer target(myfile);
    target.dosheader_analysis();
    target.dosstub_analysis();
    target.file_header_analysis();
    target.optional_header_analysis();


    return 0;
}

bool readfile(std::string filepath, std::ifstream& myfile) {
    myfile.open(filepath.c_str(), std::ios::binary);
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
*/