#ifndef API_H
#define API_H

#include <fstream>
#include <string>
#include <iomanip>
#include <sstream>
#include <type_traits>

#include "peanalyzer.h"
#include "database.h"

/* Translator类成员说明
	vector_to_hexstring()        ：vector<uint8_t>转十六进制表示形式的string类
	hexstring_to_ascii()         ：十六进制表示形式的string类转ascii码表示形式的string类
	generate_file_display()      ：将原始文件数据转换为十六进制视图
	hexadecimal_document_export()：将十六进制视图导出为txt文本文件
*/
class Translator {
public:
    Structuresults data_container;

private:
    // 类型转换
    template<typename T>
    std::string uint_to_hex_string(T num, bool with_prefix = true, int width = 8) {
        static_assert(std::is_unsigned_v<T>, "T must be unsigned integer type");

        std::stringstream ss;

        if (with_prefix) {
            ss << "0x";
        }

        ss << std::hex << std::uppercase;
        ss << std::setw(width);
        ss << std::setfill('0');
        ss << num;

        return ss.str();
    }
    template<typename T>
    std::string uint_to_dec_string(T num, bool with_comma = false) {
        static_assert(std::is_unsigned_v<T>, "T must be unsigned integer type");
        return std::to_string(num);
        /*std::stringstream ss;
        ss << num;
        return ss.str();*/
    }

    std::string vector_to_hexstring(const std::vector<uint8_t>& input_data);
    std::string hexstring_to_ascii(const std::string& hexstring);
    std::string generate_file_display(const std::vector<uint8_t>& input_data);

    // 单块翻译
    std::string single_item_degree_translator(Core::Severity severity);
    std::string single_item_translator(Core::Diagnostic single_item);

    std::string get_sct_address_table();

    // 写文件
    bool string_to_file_append(const std::wstring& export_filepath, const std::string& input_data);

    // 整合翻译
    std::string basic_file_info_translator();
    std::string aggregate_info_translator();
    std::string detailed_file_info_translator();

public:
    bool hexadecimal_document_export(const std::wstring& export_filepath);
    bool scan_report_export(const std::wstring& export_filepath);
};

/*
FundamentalAnalysis类成员说明
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
    Translator data_manager;
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
			data_manager = other.data_manager;
            file_size = other.file_size;
        }
        return *this;
    }
};

#endif // !API_H