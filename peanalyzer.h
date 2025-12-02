#ifndef PEANALYZER_H
#define PEANALYZER_H
#include <vector>
#include <cstdint>

#include "database.h"

/*
   pedata                    ：文件流
   shared_structure          ：关键字段提取结构体
                             ：int8_t型数据 = 2 时表示无法判断值是否合法
   mulbuffer[]               ：复用缓冲区

   clear_buffer()            ：清空复用缓冲区
   field_interpretation()    ：fileheader中machine字段的解析函数
   magic_joint_check()       ：magic字段一致性联合验证函数
   joint_judge_magic()       ：magic字段反推函数

   mzcheck()                 ：MZ签名检查函数
   dosheader_analysis()      ：DOS头分析函数
   signaturecheck()          ：PE签名检查函数
   file_header_analysis()    ：文件头分析函数
   optional_header_analysis()：可选头分析函数
   section_headers_analisis()：节区头分析函数
*/

struct SharedStructure {
    uint32_t peheader_offset_;        // NT头偏移
    int8_t peheader_offset_isvalid_ = true;
    uint16_t machine_;                // 目标CPU架构
    uint16_t number_of_sections_;     // 节区数量
    uint16_t size_of_optionalheader_; // 可选头大小
    int8_t machine_isvalid_ = true;
    int8_t number_of_sections_isvalid_ = true;
    int8_t size_of_optionalheader_isvalid = true;

    /* x32、x64架构 */
    uint16_t magic_;
    uint32_t address_of_entrypoint_;  // 入口点RVA（相对于ImageBase）
    uint32_t imagebase32_;
    uint64_t imagebase64_;            // 进程内存中的优先加载地址
    uint32_t section_alignment_;      // 内存中的节区对齐粒度
    uint32_t file_alignment_;         // 文件中的节区对齐粒度
    uint32_t size_of_image_;          // 映像在内存中的总大小
    int8_t magic_isvalid_ = true;
    int8_t address_of_entrypoint_isvalid_ = true;
    int8_t image_base_isvalid_ = true;
    int8_t section_alignment_isvalid_ = true;
    int8_t file_alignment_isvalid_ = true;
    int8_t size_of_image_isvalid_ = true;
    /* ROM架构 */
    uint32_t base_of_code_;
    uint32_t base_of_data_;
    uint32_t base_of_bss_;
    uint32_t size_of_code_;
    uint32_t size_of_initialized_data_;
    uint32_t size_of_uninitialized_data_;
    int8_t base_of_code_isvalid_ = true;
    int8_t base_of_data_isvalid_ = true;
    int8_t base_of_bss_isvalid_ = true;
    int8_t size_of_code_isvalid_ = true;
    int8_t size_of_initialized_data_isvalid_ = true;
    int8_t size_of_uninitialized_data_isvalid_ = true;

    uint32_t import_table_RVA_;       // DataDirectory[1]
    uint32_t import_table_size_;      // 导入表大小
    uint32_t relocation_table_RVA_;   // DataDirectory[5]
    uint32_t relocation_table_size_;  // 重定位表大小
    uint32_t tls_table_RVA_;          // DataDirectory[9]
    uint32_t tls_table_size_;         // TLS表大小

    uint32_t size_of_headers_;        // 所有头的大小

    uint32_t section_table_offset_;   // 节表在文件中的偏移

    int bitness_ = 32;                // bitness = 0 时表示未确定架构，需要采用三架构预分析来联合判断magic字段意义
    int advbitness_ = 32;             // 预分析时使用的架构信息，为0可判断文件无效，没有分析意义。
    bool PE_isValid_ = true;
    std::string file_extention_ = ".exe";
};

class PEanalyzer {
private:
    std::ifstream& pedata_;
    uint8_t mulbuffer[1024];

    /* 工具函数 */
    void clear_buffer();
    std::string field_interpretation(uint16_t inputmachine);
    void magic_check(uint16_t inputmagic, Diaresults& inputresult, int& bitness);
    void magic_joint_check();
    void joint_judge_magic(); // *反推函数，根据其他字段反推magic，仅在magic值无效的预分析中使用

public:
    /* 此处考虑 C++11 兼容性问题，未直接成员初始化 headbuffer = {0}，而采用循环赋值 */
    PEanalyzer(std::ifstream& file) : pedata_(file) {
        for (int i = 0; i < 256; i++) {
            mulbuffer[i] = 0;
        }
    }
    /* 调用时一定要按顺序调用 */
    bool mzcheck();
    bool dosheader_analysis();
    bool dosstub_analysis();
    bool signaturecheck();
    bool file_header_analysis();
    bool optional_header_analysis();
    bool section_headers_analisis();
};

#endif