#ifndef API_H
#define API_H

#include <fstream>
#include <string>
#include <iomanip>
#include <sstream>
#include <type_traits>

#include "peanalyzer.h"
#include "database.h"

struct ScanResultsDistribution {
    bool effective_structure = true;         // 记录结构是否有效（用于空文件加载情况排除无效结构）

    int info_distribution[20] = { 0 };       // 扫描到的普通信息分布
    int suspicious_distribution[20] = { 0 }; // 扫描到的可疑信息分布
    int warning_distribution[20] = { 0 };    // 扫描到的警告信息分布
    int error_distribution[20] = { 0 };      // 扫描到的错误信息分布（针对签名）

    int info_num;                            // 扫描到的普通信息数量
    int suspicious_num;                      // 扫描到的可疑信息数量
    int warning_num;                         // 扫描到的警告信息数量
    int error_num;                           // 扫描到的错误信息数量（针对签名）

    int type_distribution[11] = {};           // 扫描到的类型分布（参照 diagnostic_codes.h 文件 Object 中的6种类型）
};

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
    std::string generate_file_display(const std::vector<uint8_t>& input_data, unsigned int basic_address = 0);

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
    analysis_file()      ：基础分析API（分析完后仅在内存中存储结果，不做任何保存，有需要可在调用此函数后调用汇总或者文件输出函数）
    summary_file()       ：基础汇总API（在已完成基础分析的基础上进行单次结果汇总）
*/
// 对外的统一API
class FundamentalAnalysis {
private:
    std::ifstream myfile;
    uint64_t file_size;
    bool myfile_loaded = false;

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
    ScanResultsDistribution summary_file();

    FundamentalAnalysis& operator=(const FundamentalAnalysis& other) {
        if (this != &other) {
			data_manager = other.data_manager;
            file_size = other.file_size;
        }
        return *this;
    }
};

#endif // !API_H