#ifndef DATABASE_H
#define DATABASE_H

#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <cctype>

#include "diagnostic_codes.h"
#include "peanalyzer.h"

/*
结构体说明
    StructuralImformation          ：结构是否存在可疑或异常的收录表
    Diaresults                     ：单个结构具体诊断结果
    SectionImformation             ：单个节区信息（标准、偏移、属性）
    SectionRange                   ：节区范围
	error_category                 ：错误码枚举
	CrashReport                    ：崩溃报告
    OverlapProcessing              ：重叠数据信息
类说明
	Structuresults                 ：输出结果&数据库，建议把所有该类命名为data_container，避免出现未知错误，除非有明确需求
类成员说明
    architecture                   ：架构
    sr_file_size_                  ：文件大小，sr前缀是为了和PEanalyzer类的file_size_成员做区分
    max_number_of_possible_sections：扫描的可能最大节区数量
	m_orderliness                  ：内存映射区间是否有序
	s_orderliness                  ：文件映射区间是否有序
    memory_interval_table          ：节区内存分布区间表
    storage_interval_table         ：节区文件分布区间表
    source_file_data               ：源文件数据
其他函数说明
    is_this_section_valid()        ：某40字节数据是否可能为节区头的检查函数
    file_confidence_detection()    ：文件置信度检测（有多大可能是PE文件？）
*/

struct StructuralImformation {
    bool dos_header_normal_ = true;

    bool dos_stub_normal_ = true;
    bool dos_stub_exist_ = true;

    bool file_header_normal_ = true;
    bool optional_header_normal_ = true;

    bool section_header_normal_ = true;
    bool section_header_exist_ = true;
};

struct Diaresults {
    std::string component_name_;        // 结构名称
    // std::string component_type_;        // 结构类型"header", "section", "table"
    uint32_t file_offset_ = 0;          // 在文件中的偏移
    uint32_t data_size_ = 0;            // 数据大小

    bool isvalid = true;                // 格式是否有效
    bool issuspicious = false;          // 是否可疑
    uint32_t confidence_level_ = 100;   // 置信度 (0-100)，暂时闲置
    std::vector<std::string> evidence_; // 判断依据，暂时闲置

	std::vector<Core::Diagnostic> information_list_; // 扫描信息表
    std::vector<Core::Diagnostic> additional_information; // 额外信息，暂时闲置
};

/*struct BreakDown {
    int abnormal_num_of_keywords_ = 0; // 异常关键字段数量
    int total_num_of_keywords_ = 23;    // 关键字段总数量
};
*/

struct SectionImformation {
    bool marked_section = false;             // 是否存在不可执行可能
    bool known_combination_ = false;         // 是否为已知属性节区，如text、code等标准节区，名称和属性需要完全满足
    uint32_t offset_of_file_base = 0;        // 文件（磁盘）中的偏移（基址为0）

    /* 目前仅判断前 7 个特征 属性 */
    bool mem_execute_ = false;               // 内存可执行
    bool mem_read_ = false;                  // 内存可读
    bool mem_write_ = false;                 // 内存可写
    bool mem_shared_ = false;                // 内存共享
    bool cnt_code_ = false;                  // 包含可执行代码
    bool cnt_initialized_data_ = false;      // 包含已初始化数据
    bool cnt_uninitialized_data_ = false;    // 零初始化
    /* 下面的属性目前没用，不涉及任何判断信息 */
    bool mem_discardable_ = false;           // 使用后释放
    bool image_scn_lnk_info_ = false;        // 包含链接器信息
    bool image_scn_lnk_remove_ = false;      // 链接后删除

    bool image_scn_type_no_pad_ = false;     // 不填充对齐（不常用）
    bool image_scn_align_ = false;           // 对齐方式（1 - 8192字节）
    bool image_scn_lnk_nreloc_ovfl_ = false; // 重定位溢出

    bool image_scn_mem_not_cached_ = false;  // 不缓存 硬件相关
    bool image_scn_mem_not_paged_ = false;   // 不可分页 驱动代码
    bool image_scn_mem_purgeable_ = false;   // 可清除 资源
    bool image_scn_mem_16bit_ = false;       // 16位代码（旧）

    bool image_scn_lnk_comdat = false;       // COMDAT记录
    bool image_scn_gprel = false;            // 包含GP相对数据
    bool image_scn_mam_fardata = false;      // 远数据
};

struct SectionRange {
    size_t index;              // 节区头索引，从0开始
    uint64_t begin;            // 起始地址（或偏移）
    uint64_t end;              // 结束地址（或偏移，这里是总长，包括对齐数据）
    uint64_t size;             // 有效长度
    uint64_t alignment_length; // 对齐长度

    SectionRange(uint8_t idx, uint32_t bgn, uint32_t ed, uint32_t siz, uint32_t alth):
        index(idx), begin(bgn), end(ed), size(siz), alignment_length(alth){}
};

enum error_category {
    UNKNOWN_ERROR,
    // 文件操作错误
    FILE_OPEN_FAILED,
    FILE_SEEK_FAILED,
    FILE_READ_FAILED,
    FILE_TRUNCATED,        // 文件被截断
    FILE_TOO_SMALL,        // 文件太小
    // 指针/偏移错误
    SEEK_BEFORE_BOF,       // 移动到文件开头之前
    SEEK_AFTER_EOF,        // 移动到文件末尾之后
    INVALID_OFFSET,        // 无效的偏移值
    OFFSET_OUT_OF_RANGE,   // 偏移超出范围
    // 缓冲区错误
    BUFFER_OVERFLOW,       // 缓冲区溢出
    BUFFER_UNDERFLOW,      // 读取数据不足
    INVALID_BUFFER_ACCESS, // 无效的缓冲区访问
    MEMCPY_OUT_OF_BOUNDS,  // memcpy越界
    // 资源限制错误
    BUFFER_TOO_SMALL,      // 缓冲区太小
    OUT_OF_MEMORY,
    // 逻辑错误
    LOGIC_ERROR,
    UNREACHABLE_CODE
};

struct CrashReport {
    std::string error_code_;
    std::string message_;
};

struct OverlapProcessing {
    std::vector<uint8_t> overlapping_data;
    unsigned int length;
    size_t expectation_offset;
    size_t actual_offset;
};

struct ComprehensiveInfo {
    // 已启用
    uint64_t file_size_copy_;              // 文件大小
    std::string file_identification_ = ""; // 32位、64位或其他
    std::string architecture_ = "";        // 运行架构

    int abnormal_num_of_keywords_ = 0;     // 异常关键字段数量
    int total_num_of_keywords_ = 23;       // 关键字段总数量

    /* shared_structure迁移数据 */
    bool PE_isvalid_ = true;               // 可能是一个PE文件吗
    std::string file_extention_ = ".exe";  // 文件后缀

    // 迁移中
    /* shared_structure迁移数据*/
    uint32_t section_table_offset_;    // 节区在文件中的偏移
    uint32_t clothest_section_offset_; // 可选头后的最近的节区偏移
    int detected_section_count_ = 0;   // 实际检测出的节区数量
};

#pragma pack(push, 1)
struct DOSHeader {
    uint16_t e_magic;    // "MZ" 魔术字 (0x5A4D)
    uint16_t e_cblp;     // 最后页字节数
    uint16_t e_cp;       // 文件页数
    uint16_t e_crlc;     // 重定位数
    uint16_t e_cparhdr;  // 头部段数
    uint16_t e_minalloc; // 最小额外段
    uint16_t e_maxalloc; // 最大额外段
    uint16_t e_ss;       // 初始SS值
    uint16_t e_sp;       // 初始SP值
    uint16_t e_csum;     // 校验和
    uint16_t e_ip;       // 初始IP值
    uint16_t e_cs;       // 初始CS值
    uint16_t e_lfarlc;   // 重定位表偏移
    uint16_t e_ovno;     // 覆盖号
    uint16_t e_res[4];   // 保留字
    uint16_t e_oemid;    // OEM标识符
    uint16_t e_oeminfo;  // OEM信息
    uint16_t e_res2[10]; // 保留字
    uint32_t e_lfanew;   // PE头偏移地址（关键字段！）
};

struct FileHeader {
	uint32_t signature;            // "PE\0\0" 魔术字 (0x00004550)
    uint16_t machine;              // 目标CPU架构（如0x014C=Intel 386）
    uint16_t numberofsections;     // 节区数量
    uint32_t timedatestamp;        // 编译时间戳
    uint32_t pointertosymboltable; // 符号表偏移（调试用）
    uint32_t numberofsymbols;      // 符号数量
    uint16_t sizeofoptionalheader; // 可选头大小
    uint16_t characteristics;      // 文件属性（如可执行/DLL）
};

struct DataDirectory {
    uint32_t VirtualAddress;       // 数据的 RVA（相对虚拟地址）
    uint32_t Size;                 // 数据的大小（字节数）
};

struct OptionalHeader32 {
    uint16_t Magic;                       // 标识：0x10B=32位，0x20B=64位
    uint8_t MajorLinkerVersion;           // 链接器主版本号
    uint8_t MinorLinkerVersion;           // 链接器次版本号
    uint32_t SizeOfCode;                  // 所有代码段的总大小
    uint32_t SizeOfInitializedData;       // 已初始化数据的总大小
    uint32_t SizeOfUninitializedData;     // 未初始化数据（BSS）的总大小
    uint32_t AddressOfEntryPoint;         // 入口点RVA（相对于ImageBase）
    uint32_t BaseOfCode;                  // 代码段的起始RVA
    uint32_t BaseOfData;                  // 数据段的起始RVA（仅32位存在）

    uint32_t ImageBase;                   // 进程内存中的优先加载地址
    uint32_t SectionAlignment;            // 内存中的节区对齐粒度（通常0x1000）
    uint32_t FileAlignment;               // 文件中的节区对齐粒度（通常0x200）
    uint16_t MajorOperatingSystemVersion; // 要求的最低OS主版本
    uint16_t MinorOperatingSystemVersion; // 要求的最低OS次版本
    uint16_t MajorImageVersion;           // 映像主版本号（用户定义）
    uint16_t MinorImageVersion;           // 映像次版本号（用户定义）
    uint16_t MajorSubsystemVersion;       // 子系统主版本（通常4=Win95）
    uint16_t MinorSubsystemVersion;       // 子系统次版本
    uint32_t Win32VersionValue;           // 保留（必须为0）
    uint32_t SizeOfImage;                 // 映像在内存中的总大小
    uint32_t SizeOfHeaders;               // 所有头部的总大小（对齐后）
    uint32_t CheckSum;                    // 校验和（驱动/DLL常用）
    uint16_t Subsystem;                   // 子系统类型（1=Native，2=GUI，3=CUI）
    uint16_t DllCharacteristics;          // DLL属性（如ASLR/DEP）
    uint32_t SizeOfStackReserve;          // 初始保留的栈大小
    uint32_t SizeOfStackCommit;           // 初始提交的栈大小
    uint32_t SizeOfHeapReserve;           // 初始保留的堆大小
    uint32_t SizeOfHeapCommit;            // 初始提交的堆大小
    uint32_t LoaderFlags;                 // 保留（已废弃）
    uint32_t NumberOfRvaAndSizes;         // 数据目录项数（通常16）
    DataDirectory DataDirectory[16];      // 数据目录表
};

struct OptionalHeader64 {
    uint16_t Magic;                       // 标识：0x20B=64位
    uint8_t MajorLinkerVersion;           // 链接器主版本号
    uint8_t MinorLinkerVersion;           // 链接器次版本号
    uint32_t SizeOfCode;                  // 所有代码段的总大小
    uint32_t SizeOfInitializedData;       // 已初始化数据的总大小
    uint32_t SizeOfUninitializedData;     // 未初始化数据（BSS）的总大小
    uint32_t AddressOfEntryPoint;         // 入口点RVA（相对于ImageBase）
    uint32_t BaseOfCode;                  // 代码段的起始RVA

    uint64_t ImageBase;                   // 64位：扩展为64位地址
    uint32_t SectionAlignment;            // 内存中的节区对齐粒度
    uint32_t FileAlignment;               // 文件中的节区对齐粒度
    uint16_t MajorOperatingSystemVersion; // 要求的最低OS主版本
    uint16_t MinorOperatingSystemVersion; // 要求的最低OS次版本
    uint16_t MajorImageVersion;           // 映像主版本号
    uint16_t MinorImageVersion;           // 映像次版本号
    uint16_t MajorSubsystemVersion;       // 子系统主版本
    uint16_t MinorSubsystemVersion;       // 子系统次版本
    uint32_t Win32VersionValue;           // 保留（必须为0）
    uint32_t SizeOfImage;                 // 映像在内存中的总大小
    uint32_t SizeOfHeaders;               // 所有头部的总大小
    uint32_t CheckSum;                    // 校验和
    uint16_t Subsystem;                   // 子系统类型
    uint16_t DllCharacteristics;          // DLL属性
    uint64_t SizeOfStackReserve;          // 64位：扩展为64位
    uint64_t SizeOfStackCommit;           // 64位：扩展为64位
    uint64_t SizeOfHeapReserve;           // 64位：扩展为64位
    uint64_t SizeOfHeapCommit;            // 64位：扩展为64位
    uint32_t LoaderFlags;                 // 保留（已废弃）
    uint32_t NumberOfRvaAndSizes;         // 数据目录项数（通常16）
    DataDirectory DataDirectory[16];      // 数据目录表
};

struct ROM_OptionalHeader {
    uint8_t Magic;                        // 0x107 - ROM 魔数
    uint16_t MajorLinkerVersion;          // 链接器主版本号
    uint16_t MinorLinkerVersion;          // 链接器次版本号
    uint32_t SizeOfCode;                  // 所有代码段的总大小
    uint32_t SizeOfInitializedData;       // 初始化数据的总大小
    uint32_t SizeOfUninitializedData;     // 未初始化数据的总大小（通常为0）
    uint32_t AddressOfEntryPoint;         // 入口点地址（ROM中的偏移）
    uint32_t BaseOfCode;                  // 代码段的基址
    uint32_t BaseOfData;                  // 数据段的基址

    uint32_t BaseOfBss;                   // BSS段基址（未初始化数据）
    uint32_t GprMask;                     // 通用寄存器掩码
    uint32_t CprMask[4];                  // 协处理器寄存器掩码
    uint32_t GpValue;                     // 全局指针值
};

struct SectionHeader {
    uint8_t  Name[8];                     // 节区名称（如 ".idata"）
    uint32_t VirtualSize;                 // 内存中节区实际大小（可能未对齐）
    uint32_t VirtualAddress;              // 内存中的 RVA（关键！用于计算）
    uint32_t SizeOfRawData;               // 文件中节区大小（对齐后）
    uint32_t PointerToRawData;            // 文件中的偏移（关键！用于计算）
    uint32_t PointerToRelocations;        // 重定位表偏移（无用，除非是OBJ文件）
    uint32_t PointerToLinenumbers;        // 调试信息（通常为0）
    uint16_t NumberOfRelocations;         // 重定位项数（无用）
    uint16_t NumberOfLinenumbers;         // 调试信息（通常为0）
    uint32_t Characteristics;             // 节区属性（如可读/可写）
};
#pragma pack(pop)

class Structuresults {
public:
    // 基础信息
    /* 
    output_range 输出范围说明（不可用户管理，默认尽量输出所有结果）：
        1 - 输出至 40 byte 扫描结果
        2 - 输出至 PE 签名前扫描结果
        3 - 输出至 PE 签名后 20 byte 扫描结果
        4 - 输出至节区头前的扫描结果
        5 - 输出文件头部内容所有扫描结果
    */
    int output_range_ = 5;
    ComprehensiveInfo comprehensive_info_;
 
    StructuralImformation structures_attributes;

    // 诊断数据
    std::vector<Diaresults> diarelist{};

    std::vector<SectionImformation> section_attributes;
	int max_number_of_possible_sections = 0;
	bool m_orderliness = true; // 节区内存布局和节区头顺序是否一致，有序 = true，无序 = false
    bool s_orderliness = true; // 节区文件布局和节区头顺序是否一致，同上
    std::vector<SectionRange> memory_interval_table;
    std::vector<SectionRange> storage_interval_table;

    // 原始文件数据（数据显示使用）
    std::vector<OverlapProcessing> overlapping_area;
    std::vector<uint8_t> source_file_data;

    // 原始文件映射数据（数据处理使用）
    DOSHeader dosheader{};
    std::vector<uint8_t> dosstub;
    FileHeader fileheader{};
    OptionalHeader32 optionalheader32{};
    OptionalHeader64 optionalheader64{};
    ROM_OptionalHeader optionalheaderrom{};
    std::vector<SectionHeader> sectionheaders;

    // 崩溃报告（文件加载失败等原因未能成功分析）
	CrashReport crashreport{};
    void crash_imformation_set(error_category code, const std::string& msg = "");
};

int is_this_section_valid(const SectionHeader& header, SharedStructure shared_structure);
int file_confidence_detection(SharedStructure shared_structure);

#endif