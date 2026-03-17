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

public:
    structuresults data_container;
    enum class error_code {
        SUCCESS = 0,
        FILE_NOT_FOUND,
        FILE_ACCESS_DENIED,
        UNKNOWN_ERROR
    };

    error_code analysis_file(const std::string input_filepath);
};