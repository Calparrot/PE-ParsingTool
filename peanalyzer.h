#ifndef PEANALYZER_H
#define PEANALYZER_H
#include <vector>
#include <cstdint>

#include "database.h"

/*
结构体说明
    SharedStructure                ：关键字段提取结构体
类说明
	PEanalyzer                     ：PE文件分析类
类成员说明
    pedata                         ：文件流
    mulbuffer[]                    ：复用缓冲区
    read_offset                    ：复用缓冲区指针偏移

    clear_buffer()                 ：清空复用缓冲区
    field_interpretation()         ：fileheader中machine字段的解析函数
	magic_check()                  ：magic字段单架构验证函数
    magic_joint_check()            ：magic字段一致性联合验证函数
    joint_judge_magic()            ：magic字段反推函数
    section_characteristic_judge() ：节区属性判断函数
    section_characteristic_check() ：节区属性常见冲突组合验证函数
	section_name_match()           ：节区常用名称匹配函数
    section_name_check()           ：节区常用名称检验和属性联合判断函数

    mzcheck()                      ：MZ签名检查函数
    dosheader_analysis()           ：DOS头分析函数
    signaturecheck()               ：PE签名检查函数
    file_header_analysis()         ：文件头分析函数
    optional_header_analysis()     ：可选头分析函数
    section_headers_analisis()     ：节区头分析函数
*/

extern uint64_t file_size;

enum class EleCorrectness : uint8_t {
    not_valid = 0,
    valid = 1,
    uncertain = 2
};

struct SharedStructure {
    uint32_t peheader_offset_;        // NT头偏移
    EleCorrectness peheader_offset_isvalid_ = EleCorrectness::valid;
    uint16_t machine_;                // 目标CPU架构
    uint16_t number_of_sections_;     // 节区数量
    uint16_t size_of_optionalheader_; // 可选头大小
    EleCorrectness machine_isvalid_ = EleCorrectness::valid;
    EleCorrectness number_of_sections_isvalid_ = EleCorrectness::valid;
    EleCorrectness size_of_optionalheader_isvalid = EleCorrectness::valid;

    /* x32、x64架构 */
    uint16_t magic_;
    uint32_t address_of_entrypoint_;  // 入口点RVA（相对于ImageBase）
    uint32_t imagebase32_;
    uint64_t imagebase64_;            // 进程内存中的优先加载地址
    uint32_t section_alignment_;      // 内存中的节区对齐粒度
    uint32_t file_alignment_;         // 文件中的节区对齐粒度
    uint32_t size_of_image_;          // 映像在内存中的总大小
    EleCorrectness magic_isvalid_ = EleCorrectness::valid;
    EleCorrectness address_of_entrypoint_isvalid_ = EleCorrectness::valid;
    EleCorrectness image_base_isvalid_ = EleCorrectness::valid;
    EleCorrectness section_alignment_isvalid_ = EleCorrectness::valid;
    EleCorrectness file_alignment_isvalid_ = EleCorrectness::valid;
    EleCorrectness size_of_image_isvalid_ = EleCorrectness::valid;
    /* ROM架构 */
    uint32_t base_of_code_;
    uint32_t base_of_data_;
    uint32_t base_of_bss_;
    uint32_t size_of_code_;
    uint32_t size_of_initialized_data_;
    uint32_t size_of_uninitialized_data_;
    EleCorrectness base_of_code_isvalid_ = EleCorrectness::valid;
    EleCorrectness base_of_data_isvalid_ = EleCorrectness::valid;
    EleCorrectness base_of_bss_isvalid_ = EleCorrectness::valid;
    EleCorrectness size_of_code_isvalid_ = EleCorrectness::valid;
    EleCorrectness size_of_initialized_data_isvalid_ = EleCorrectness::valid;
    EleCorrectness size_of_uninitialized_data_isvalid_ = EleCorrectness::valid;

    uint32_t import_table_RVA_;        // DataDirectory[1]
    uint32_t import_table_size_;       // 导入表大小
    uint32_t relocation_table_RVA_;    // DataDirectory[5]
    uint32_t relocation_table_size_;   // 重定位表大小
    uint32_t tls_table_RVA_;           // DataDirectory[9]
    uint32_t tls_table_size_;          // TLS表大小

    uint32_t size_of_headers_;         // 所有头的大小
    int64_t size_of_file_ = file_size; // 文件大小

    uint32_t section_table_offset_;    // 节区在文件中的偏移
    uint32_t clothest_section_offset_; // 可选头后的最近的节区偏移
    int detected_section_count_ = 0;   // 实际检测出的节区数量

    int bitness_ = 32;                 // bitness = 0 时表示未确定架构，需要采用三架构预分析来联合判断magic字段意义
    int advbitness_ = 32;              // 预分析时使用的架构信息，为0可判断文件无效，没有分析意义。
    bool PE_isValid_ = true;
    std::string file_extention_ = ".exe";
};

class PEanalyzer {
private:
    std::ifstream& pedata_;
    uint8_t mulbuffer[5600] = { 0 };
    size_t read_offset = 0;

    /* 临时工具函数 */
    void clear_buffer();
    std::string field_interpretation(uint16_t inputmachine);
    void magic_check(uint16_t inputmagic, Diaresults& inputresult, int& bitness);
    void magic_joint_check();
    void magic_joint_judge(); // *反推函数，根据其他字段反推magic，仅在magic值无效的预分析中使用
    void section_characteristic_judge(uint32_t input_characteristic);
    void section_characteristic_check(uint32_t input_characteristic, Diaresults& inputresult, size_t num);
	int section_name_match(const uint8_t input_name[8]);
    void section_name_check(const uint8_t input_name[8], const uint32_t input_characteristic, Diaresults& inputresult, size_t num);

public:
    PEanalyzer(std::ifstream& inputfile) : pedata_(inputfile) {}
    /* 调用时一定要按顺序调用 */
    bool dosheader_analysis();
    bool dosstub_analysis();
    bool file_header_analysis();
    bool optional_header_analysis();
    bool section_headers_analysis();
};

#endif