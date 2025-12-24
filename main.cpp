#include <iostream>
#include <string>
#include <fstream>

#include "peanalyzer.h"

/*
    filepath：目标文件路径
    myfile  ：目标文件流
    target  ：目标文件解析器（一阶段）
*/

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