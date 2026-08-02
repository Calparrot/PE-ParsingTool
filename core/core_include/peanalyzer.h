#pragma once
#include <vector>
#include <cstdint>
#include <fstream>

/*
 * ============================================================================
 *  PE 基础分析模块 - 类型速查
 * ============================================================================
 *
 *  STRUCTS（结构体）
 *  - EleCorrectness                    自定义三态枚举（用于增强布尔值）
 *  - SharedStructure                   关键信息速查表
 *
 *  CLASSES（类）
 *  - PEanalyzer                        PE 基础分析类
 *
 *  MEMBERS - PEanalyzer 核心成员
 *  - pedata_                           接收的文件流
 *  - mulbuffer_[]                      复用缓冲区
 *  - read_offset_                      复用缓冲区指针偏移
 *  - shared_structure_                 关键信息速查表
 *  - file_size                         文件大小
 *
 *  FUNCTIONS（函数）
 *  【PEanalyzer 类成员函数（private）说明】
 *  - clear_buffer()                    清空复用缓冲区
 *  - field_interpretation()            fileheader中machine字段的解析函数
 *  - magic_check()                     magic字段单架构验证函数
 *  - magic_joint_check()               magic字段一致性联合验证函数
 *  - magic_joint_judge()               magic字段反推函数，仅在magic值无效的预分析中使用
 *  - section_characteristic_judge()    节区属性判断函数
 *  - section_characteristic_check()    节区属性常见冲突组合验证函数
 *  - section_name_match()              节区常用名称匹配函数
 *  - section_name_check()              节区常用名称检验和属性联合判断函数
 * 
 *  【PEanalyzer 类成员函数（public）说明】
 *  - dosheader_analysis()              DOS头分析函数
 *  - dosstub_analysis()                DOS存根分析函数
 *  - file_header_analysis()            文件头分析函数
 *  - optional_header_analysis()        可选头分析函数
 *  - section_headers_analysis()        节区头分析函数
 *  - import_descriptor_seeker()        导入表基础结构分析
 * 
 * ============================================================================
 */

/* 前置声明 */
class Structuresults;
struct Diaresults;

enum class EleCorrectness : uint8_t {
    not_valid = 0,
    valid = 1,
    uncertain = 2
};

struct SharedStructure {
    uint32_t peheader_offset = 0;

    /* x32、x64架构 */
    uint16_t magic = 0;
    uint32_t address_of_entrypoint = 0;
    uint32_t imagebase32 = 0;
    uint64_t imagebase64 = 0;
    uint32_t section_alignment = 0;
    uint32_t file_alignment = 0;
    uint32_t size_of_image = 0;

    EleCorrectness magic_isvalid = EleCorrectness::valid;
    EleCorrectness address_of_entrypoint_isvalid = EleCorrectness::valid;
    EleCorrectness image_base_isvalid = EleCorrectness::valid;
    EleCorrectness section_alignment_isvalid = EleCorrectness::valid;
    EleCorrectness file_alignment_isvalid = EleCorrectness::valid;
    EleCorrectness size_of_image_isvalid = EleCorrectness::valid;

    /* ROM架构 */
    uint32_t base_of_code = 0;
    uint32_t base_of_data = 0;
    uint32_t base_of_bss = 0;
    uint32_t size_of_code = 0;
    uint32_t size_of_initialized_data = 0;
    uint32_t size_of_uninitialized_data = 0;

    EleCorrectness base_of_code_isvalid = EleCorrectness::valid;
    EleCorrectness base_of_data_isvalid = EleCorrectness::valid;
    EleCorrectness base_of_bss_isvalid = EleCorrectness::valid;
    EleCorrectness size_of_code_isvalid = EleCorrectness::valid;
    EleCorrectness size_of_initialized_data_isvalid = EleCorrectness::valid;
    EleCorrectness size_of_uninitialized_data_isvalid = EleCorrectness::valid;

    /* 数据目录表 */
    uint32_t import_table_RVA = 0;        // DataDirectory[1]
    uint32_t import_table_size = 0;       // 导入表大小
    uint32_t relocation_table_RVA = 0;    // DataDirectory[5]
    uint32_t relocation_table_size = 0;   // 重定位表大小
    uint32_t tls_table_RVA = 0;           // DataDirectory[9]
    uint32_t tls_table_size = 0;          // TLS表大小

    /* 文件信息 */
    uint32_t size_of_headers = 0;         // 所有头的大小
    uint32_t section_table_offset = 0;    // 节区在文件中的偏移
    uint32_t clothest_section_offset = 0; // 可选头后的最近的节区偏移
    int detected_section_count = 0;       // 实际检测出的节区数量
    int bitness = 32;                     // bitness = 0 时表示未确定架构，需要采用三架构预分析来联合判断magic字段意义
    int advbitness = 32;                  // 预分析时使用的架构信息，为0可判断文件无效，没有分析意义。
};

class PEanalyzer {
private:
    std::ifstream& pedata_;
    uint8_t mulbuffer_[5600] = { 0 };
    size_t read_offset_ = 0;

    SharedStructure shared_structure_ = SharedStructure();

public:
    int64_t file_size = 0;

private:
    void clear_buffer();
    std::string field_interpretation(uint16_t inputmachine);
    void magic_check(uint16_t inputmagic, Diaresults& inputresult, int& bitness);
    void magic_joint_check();
    void magic_joint_judge();
    void section_characteristic_judge(uint32_t input_characteristic, Structuresults& data_container);
    void section_characteristic_check(uint32_t input_characteristic, Diaresults& inputresult, size_t num, Structuresults& data_container);
	int section_name_match(const uint8_t input_name[8]);
    void section_name_check(const uint8_t input_name[8], const uint32_t input_characteristic, Diaresults& inputresult, size_t num, Structuresults& data_container);

public:
    /* 调用时按顺序调用，用户不可管理，由API统一封装 */
    // 头部基础结构分析
    bool dosheader_analysis(Structuresults& data_container);
    bool dosstub_analysis(Structuresults& data_container);
    bool file_header_analysis(Structuresults& data_container);
    bool optional_header_analysis(Structuresults& data_container);
    bool section_headers_analysis(Structuresults& data_container);

    // 导入表基础结构分析
    bool import_descriptor_seeker(Structuresults& data_container);

    /* 构造函数 */
    PEanalyzer(std::ifstream& inputfile) : pedata_(inputfile) {
        auto& file = pedata_;

        if (!file) {
            throw std::runtime_error("PEanalyzer: Invalid file stream");
        }
        std::streampos current = file.tellg();
        if (current == static_cast<std::streampos>(-1)) {
            throw std::runtime_error("PEanalyzer: Failed to get current file position");
        }

        file.clear();

        file.seekg(0, std::ios::end);
        if (!file) {
            file.clear();
            file.seekg(current);
            throw std::runtime_error("PEanalyzer: Failed to seek to end of file");
        }
        std::streampos endPos = file.tellg();
        if (endPos == static_cast<std::streampos>(-1)) {
            file.clear();
            file.seekg(current);
            throw std::runtime_error("PEanalyzer: Failed to get file size");
        }
        file_size = static_cast<int64_t>(endPos);
        file.seekg(current);
        if (!file) {
            file.clear();
            file.seekg(0, std::ios::beg);
        }
    }
};