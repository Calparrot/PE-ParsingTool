#pragma once
#ifndef API_H
#define API_H
#endif // !API_H

#include <fstream>
#include <string>

#include "peanalyzer.h"
#include "database.h"

/*
类成员说明
    myfile               ：文件路径
    file_size            ：传入的文件大小
    readfile()           ：将文件从外存读到内存中的文件流缓冲区并存储源文件数据
    check_little_endian()：小端序检查
    data_container       ：扫描信息和错误信息
    organised_data[]     ：综合性源文件信息
    analysis_file()      ：基础分析API
*/

// 对外的统一API
class FundamentalAnalysis {
private:
    std::ifstream myfile;
    uint64_t file_size;

    bool readfile(std::string filepath);
    bool check_little_endian();

public:
    structuresults data_container;
    enum class error_code {
        SUCCESS = 0,
        FILE_NOT_FOUND,
        FILE_ACCESS_DENIED,
        PLATFORM_NOT_SUPPORTED,
        UNKNOWN_ERROR
    };

    error_code analysis_file(const std::string input_filepath);

    FundamentalAnalysis& operator=(const FundamentalAnalysis& other) {
        if (this != &other) {
            data_container = other.data_container;
            file_size = other.file_size;
        }
        return *this;
    }
};