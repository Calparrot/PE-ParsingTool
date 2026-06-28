#pragma once
#include <fstream>
#include <string>
#include <iomanip>
#include <sstream>
#include <type_traits>
#include <vector>

#include "peanalyzer.h"
#include "database.h"
#include "recheck.h"
#include "recheck_data.h"

struct ScanResultsDistribution {
    bool effective_structure = true;         // 记录结构是否有效（用于空文件加载情况排除无效结构）

    int info_distribution[20] = { 0 };       // 扫描到的普通信息分布
    int suspicious_distribution[20] = { 0 }; // 扫描到的可疑信息分布
    int warning_distribution[20] = { 0 };    // 扫描到的警告信息分布
    int error_distribution[20] = { 0 };      // 扫描到的错误信息分布（针对签名）

    int info_num = 0;                        // 扫描到的普通信息数量
    int suspicious_num = 0;                  // 扫描到的可疑信息数量
    int warning_num = 0;                     // 扫描到的警告信息数量
    int error_num = 0;                       // 扫描到的错误信息数量（针对签名）

    int type_distribution[11] = {};          // 扫描到的类型分布（参照 diagnostic_codes.h 文件 Object 中的6种类型）
};

/* Translator类成员说明
private成员函数：
	uint_to_hex_string()		   ：无符号整数（uint8_t、uint16_t等）转十六进制表示形式的string类
	uint_to_dec_string()           ：无符号整数（uint8_t、uint16_t等）转十进制表示形式的string类
	vector_to_hexstring()          ：vector<uint8_t>转十六进制表示形式的string类
	hexstring_to_ascii()           ：十六进制表示形式的string类转ascii码表示形式的string类
	generate_file_display()        ：将原始文件数据转换为十六进制视图
	single_item_degree_translator()：将单条信息严重程度翻译为字符串（如【信息】、【可疑】等）形式
	single_item_translator()       ：将单条信息翻译为字符串形式
	string get_sct_address_table() ：将节区地址表整理为字符串形式
	string_to_file_append()        ：将字符串形式的数据追加写入文件
	basic_file_info_translator()   ：整理扫描结果 comprehensive_info_ 为【基础扫描信息】块
    aggregate_info_translator()    ：汇总不同结构的扫描信息
	detailed_file_info_translator()：整理扫描结果 diarelist 为【详细信息】块
public成员函数：
	hexadecimal_document_export()  ：将十六进制视图导出为txt文本文件
	scan_report_export()		   ：将扫描报告导出为txt文本文件
    print_report()                 ：在终端打印扫描报告
*/
class Translator {
public:
    Structuresults data_container;
    SecondaryRecord recheck_container;

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

    std::string get_sct_address_table();       // 节表
    std::string get_import_descriptor_table(); // 导入表
    std::string get_INT_table();               // 导入函数
    std::string get_import_module_name();      // 导入模块名称

    // 写文件
    bool string_to_file_append(const std::string& export_filepath_utf8, const std::string& input_data);

    // 整合翻译
    std::string basic_file_info_translator();
    std::string aggregate_info_translator();
    std::string detailed_file_info_translator();

public:
	bool hexadecimal_document_export(const std::string& export_filepath);
	bool scan_report_export(const std::string& export_filepath);
    void print_report();
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

public:
    Translator data_manager;
    struct Config {
        bool detailed_analysis_started = false; // 是否开启详细分析

        bool detailed_header_analysis = false;  // 是否详细分析头部
        bool INT_analysis = false;              // 是否展开分析导入表
    } config;
    enum class error_code {
        SUCCESS = 0,            // 成功
        FILE_NOT_FOUND,         // 未找到文件
        FILE_ACCESS_DENIED,     // 文件打开失败
        PLATFORM_NOT_SUPPORTED, // 非小端序
        PROCESS_ERROR,          // 流程出错
        UNKNOWN_ERROR           // 未知问题
    };

private:
    bool readfile(std::string filepath);
    bool check_little_endian();

public:
    error_code analysis_file(const std::string input_filepath);
    error_code recheck_file(const std::string input_filepath);
    ScanResultsDistribution summary_file();

    std::vector<bool> check_settings();
    FundamentalAnalysis& operator=(const FundamentalAnalysis& other) {
        if (this != &other) {
			data_manager = other.data_manager;
            file_size = other.file_size;
        }
        return *this;
    }
};