#pragma once
#include <string>

#include "peanalyzer.h"

extern structuresults data_container;

class PEApi {
private:
	std::ifstream myfile;
    uint64_t file_size;
    enum error_code {
        SUCCESS = 0,
        FILE_NOT_FOUND,
        FILE_ACCESS_DENIED,
        UNKNOWN_ERROR
    };

	bool readfile(std::string filepath);

public:
	error_code analysis_file(const std::string input_filepath);
};