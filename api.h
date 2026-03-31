#pragma once
#ifndef API_H
#define API_H
#endif // !API_H

#include <fstream>
#include <string>

#include "peanalyzer.h"
#include "database.h"

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

    FundamentalAnalysis& operator=(const FundamentalAnalysis& other) {
        if (this != &other) {
            data_container = other.data_container;
            file_size = other.file_size;
        }
        return *this;
    }

    error_code analysis_file(const std::string input_filepath);
};