#ifndef UTILS_H
#define UTILS_H
#include <string>

/*
    get_exe_directory()：获取本exe的文件路径
    wstring_to_utf8()  ：将wstring转string类，配合get_exe_directory()使用，支持string类的路径
*/

std::wstring get_exe_directory();
std::string wstring_to_utf8(const std::wstring& wstr); // 其实没有用上，而且可能出错

#endif // !UTILS_H