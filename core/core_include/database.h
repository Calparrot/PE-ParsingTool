#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <cctype>

#include "diagnostic_codes.h"
#include "peanalyzer.h"

/*
 * ============================================================================
 *  数据管理模块 - 类型速查
 * ============================================================================
 * 
 *  STRUCTS（结构体）
 *  - StructuralInformation     收录表（结构是否可疑/异常）
 *  - Diaresults                单个结构的诊断结果
 *  - SectionInformation        单个节区信息（标准/偏移/属性）
 *  - SectionRange              节区范围
 *  - error_category            错误码枚举
 *  - CrashReport               崩溃报告
 *  - OverlapProcessing         重叠数据信息
 *  - ComprehensiveInfo         文件信息
 *  - DOSHeader                 _IMAGE_DOS_HEADER 结构定义
 *  - FileHeader                _IMAGE_FILE_HEADER 结构定义
 *  - DataDirectory             _IMAGE_DATA_DIRECTORY 结构定义
 *  - OptionalHeader32          _IMAGE_OPTIONAL_HEADER32 结构定义
 *  - OptionalHeader64          _IMAGE_OPTIONAL_HEADER64 结构定义
 *  - ROM_OptionalHeader        _IMAGE_ROM_OPTIONAL_HEADER 结构定义
 *  - SectionHeader             _IMAGE_SECTION_HEADER 结构定义
 *  - ImportDescriptor          _IMAGE_IMPORT_DESCRIPTOR 结构定义
 *
 *  CLASSES（类）
 *  - Structuresults            扫描结果容器 → 建议重命名为 data_container
 *
 *  MEMBERS - Structuresults 核心成员
 *  - num_of_scanned_blocks_    待补充功能说明
 *  - out_range[]               扫描范围记录表（位数与结构顺序对应）
 *  - diarelist[]               文件各结构扫描诊断结果表
 *  - section_attributes[]      文件各节区属性表
 *  - max_number_of_possible_sections   最大可能节区数量（暂弃用）
 *  - m_orderliness             内存映射区间是否有序
 *  - s_orderliness             文件映射区间是否有序
 *  - memory_interval_table     节区内存分布区间表
 *  - storage_interval_table    节区文件分布区间表
 *  - overlapping_area[]        重叠数据区间表
 *  - source_file_data          源文件原始数据
 *
 *  FUNCTIONS（函数）
 *  - is_this_section_valid()       校验 40 字节是否为有效节区头
 *  - file_confidence_detection()   PE 文件置信度检测
 * 
 * 【Structuresults 类成员函数（public）说明】
 *  - crash_information_set()       崩溃报告设置
 * 
 *  ADDITIONAL NOTES（附加说明）
 *   【output_range 输出范围说明（不可用户管理，默认尽量输出所有结果）】
 *  - 1 - 输出至 40 byte 扫描结果
 *  - 2 - 输出至 PE 签名前扫描结果
 *  - 3 - 输出至 PE 签名后 20 byte 扫描结果
 *  - 4 - 输出至节区头前的扫描结果
 *  - 5 - 输出文件头部内容所有扫描结果
 * 
 * ============================================================================
 */

struct StructuralInformation {
    /* 结构地址表（左闭右开） */
    unsigned int head_start_address = 0;
    unsigned int head_end_address = 0;

    /* IMAGE_SECTION_HEADER（包括中间空洞位置） */
    unsigned int section_start_address = 0;
    unsigned int section_end_address = 0;

    /* IMAGE_IMPORT_DESCRIPTOR */
	unsigned int import_descriptor_start_address = 0;
	unsigned int import_descriptor_end_address = 0;

    /* 结构信息概况表 */
    bool dos_header_normal = true;
    bool dos_stub_normal = true;
    bool dos_stub_exist = true;

    bool file_header_normal = true;
    bool optional_header_normal = true;

	bool section_header_normal = true;
    bool section_header_exist = true;

    bool import_descriptor_found = true; // true表示成功找到IMAGE_IMPORT_DESCRIPTOR结构
};

struct Diaresults {
    std::string component_name;        // 结构名称
    uint32_t file_offset = 0;          // 在文件中的偏移
    uint32_t data_size = 0;            // 数据大小

    bool isvalid = true;               // 格式是否有效
    bool issuspicious = false;         // 是否可疑
    uint32_t confidence_level = 100;   // 置信度 (0-100)，暂时闲置
    std::vector<std::string> evidence; // 判断依据，暂时闲置

	std::vector<Core::Diagnostic> information_list;  // 扫描信息表
    std::vector<std::string> additional_information; // 额外信息
};

struct SectionInformation {
    bool marked_section = false;            // 是否存在不可执行可能
    bool known_combination = false;         // 是否为已知属性节区，如text、code等标准节区，名称和属性需要完全满足
    uint32_t offset_of_file_base = 0;       // 文件（磁盘）中的偏移（基址为0）

    /* 目前仅判断前 7 个特征 属性 */
    bool mem_execute = false;               // 内存可执行
    bool mem_read = false;                  // 内存可读
    bool mem_write = false;                 // 内存可写
    bool mem_shared = false;                // 内存共享
    bool cnt_code = false;                  // 包含可执行代码
    bool cnt_initialized_data = false;      // 包含已初始化数据
    bool cnt_uninitialized_data = false;    // 零初始化

    /* 下面的属性目前没用，不涉及任何判断信息 */
    bool mem_discardable = false;           // 使用后释放
    bool image_scn_lnk_info = false;        // 包含链接器信息
    bool image_scn_lnk_remove = false;      // 链接后删除

    bool image_scn_type_no_pad = false;     // 不填充对齐（不常用）
    bool image_scn_align = false;           // 对齐方式（1 - 8192字节）
    bool image_scn_lnk_nreloc_ovfl = false; // 重定位溢出

    bool image_scn_mem_not_cached = false;  // 不缓存 硬件相关
    bool image_scn_mem_not_paged = false;   // 不可分页 驱动代码
    bool image_scn_mem_purgeable = false;   // 可清除 资源
    bool image_scn_mem_16bit = false;       // 16位代码（旧）

    bool image_scn_lnk_comdat = false;      // COMDAT记录
    bool image_scn_gprel = false;           // 包含GP相对数据
    bool image_scn_mam_fardata = false;     // 远数据
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
	UNKNOWN_ERROR,         // 未知错误
    
    /* 文件操作错误 */
	FILE_OPEN_FAILED,      // 文件打开失败
	FILE_SEEK_FAILED,      // 文件指针移动失败
	FILE_READ_FAILED,      // 文件读取失败
    FILE_TRUNCATED,        // 文件被截断
    FILE_TOO_SMALL,        // 文件太小

    /* 指针或偏移错误 */
    SEEK_BEFORE_BOF,       // 移动到文件开头之前
    SEEK_AFTER_EOF,        // 移动到文件末尾之后
    INVALID_OFFSET,        // 无效的偏移值
    OFFSET_OUT_OF_RANGE,   // 偏移超出范围

    /* 缓冲区错误 */
    BUFFER_OVERFLOW,       // 缓冲区溢出
    BUFFER_UNDERFLOW,      // 读取数据不足
    INVALID_BUFFER_ACCESS, // 无效的缓冲区访问
    MEMCPY_OUT_OF_BOUNDS,  // memcpy越界

    /* 资源限制错误 */
    BUFFER_TOO_SMALL,      // 缓冲区太小
	OUT_OF_MEMORY,         // 内存不足

    /* 逻辑错误 */
	LOGIC_ERROR,           // 逻辑错误
	UNREACHABLE_CODE       // 不可达代码
};

struct CrashReport {
	std::string error_code; // 错误码
	std::string message;    // 错误信息
};

struct OverlapProcessing {
	std::vector<uint8_t> overlapping_data; // 重叠数据
	unsigned int length = 0;               // 重叠数据长度
	size_t expectation_offset = 0;         // 期望偏移
	size_t actual_offset = 0;              // 实际偏移
};

struct ComprehensiveInfo {
    /* 使用中 */
    /* 新增数据 */
    uint64_t file_size_copy = 0;          // 文件大小
    std::string file_identification = ""; // 32位、64位或其他
    std::string architecture = "";        // 运行架构

    int abnormal_num_of_keywords = 0;     // 异常关键字段数量
    int total_num_of_keywords = 23;       // 关键字段总数量

    /* shared_structure迁移数据 */
    bool PE_isvalid = true;               // 可能是一个PE文件吗
    std::string file_extention = ".exe";  // 文件后缀

    /* 迁移中 */
    uint32_t section_table_offset;        // 节区在文件中的偏移
    uint32_t clothest_section_offset;     // 可选头后的最近的节区偏移
    int detected_section_count = 0;       // 实际检测出的节区数量
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
    uint32_t e_lfanew;   // PE头偏移地址
};

struct FileHeader {
	uint32_t Signature;            // "PE\0\0" 魔术字 (0x00004550)
    uint16_t Machine;              // 目标CPU架构
    uint16_t NumberOfSections;     // 节区数量
    uint32_t TimedateStamp;        // 编译时间戳
    uint32_t PointerToSymbolTable; // 符号表偏移
    uint32_t NumberOfSymbols;      // 符号数量
    uint16_t SizeOfOptionalHeader; // 可选头大小
    uint16_t Characteristics;      // 文件属性
};

struct DataDirectory {
    uint32_t VirtualAddress; // 数据的 RVA
    uint32_t Size;           // 数据的大小
};

struct OptionalHeader32 {
    uint16_t Magic;                       // 标识：0x10B=32位
    uint8_t MajorLinkerVersion;           // 链接器主版本号
    uint8_t MinorLinkerVersion;           // 链接器次版本号
    uint32_t SizeOfCode;                  // 所有代码段的总大小
    uint32_t SizeOfInitializedData;       // 已初始化数据的总大小
    uint32_t SizeOfUninitializedData;     // 未初始化数据（BSS）的总大小
    uint32_t AddressOfEntryPoint;         // 入口点RVA（相对于ImageBase）
    uint32_t BaseOfCode;                  // 代码段的起始RVA
    uint32_t BaseOfData;                  // 数据段的起始RVA

    uint32_t ImageBase;                   // 进程内存中的优先加载地址
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
    uint32_t SizeOfHeaders;               // 所有头部的总大小（对齐后）
    uint32_t CheckSum;                    // 校验和
    uint16_t Subsystem;                   // 子系统类型
    uint16_t DllCharacteristics;          // DLL属性
    uint32_t SizeOfStackReserve;          // 初始保留的栈大小
    uint32_t SizeOfStackCommit;           // 初始提交的栈大小
    uint32_t SizeOfHeapReserve;           // 初始保留的堆大小
    uint32_t SizeOfHeapCommit;            // 初始提交的堆大小
    uint32_t LoaderFlags;                 // 保留（已废弃）
    uint32_t NumberOfRvaAndSizes;         // 数据目录项数
    DataDirectory DataDirectory_[16];     // 数据目录表
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
    uint32_t NumberOfRvaAndSizes;         // 数据目录项数
    DataDirectory DataDirectory_[16];     // 数据目录表
};

struct ROM_OptionalHeader {
    uint8_t Magic;                    // 标识：0x107=ROM
    uint16_t MajorLinkerVersion;      // 链接器主版本号
    uint16_t MinorLinkerVersion;      // 链接器次版本号
    uint32_t SizeOfCode;              // 所有代码段的总大小
    uint32_t SizeOfInitializedData;   // 初始化数据的总大小
    uint32_t SizeOfUninitializedData; // 未初始化数据的总大小
    uint32_t AddressOfEntryPoint;     // 入口点地址
    uint32_t BaseOfCode;              // 代码段的基址
    uint32_t BaseOfData;              // 数据段的基址

    uint32_t BaseOfBss;               // BSS段基址
    uint32_t GprMask;                 // 通用寄存器掩码
    uint32_t CprMask[4];              // 协处理器寄存器掩码
    uint32_t GpValue;                 // 全局指针值
};

struct SectionHeader {
    uint8_t  Name[8];              // 节区名称
    uint32_t VirtualSize;          // 内存中节区实际大小
    uint32_t VirtualAddress;       // 内存中的 RVA
    uint32_t SizeOfRawData;        // 文件中节区大小（对齐后）
    uint32_t PointerToRawData;     // 文件中的偏移
    uint32_t PointerToRelocations; // 重定位表偏移
    uint32_t PointerToLinenumbers; // 调试信息
    uint16_t NumberOfRelocations;  // 重定位项数
    uint16_t NumberOfLinenumbers;  // 调试信息
    uint32_t Characteristics;      // 节区属性
};

struct ImportDescriptor {
    uint32_t OriginalFirstThunk; // 指向 INT（Import Name Table）
    uint32_t TimeDateStamp;      // 时间戳
    uint32_t ForwarderChain;     // 转发链索引
    uint32_t Name;               // 指向 DLL 名称字符串（RVA）
    uint32_t FirstThunk;         // 指向 IAT（Import Address Table）
};
#pragma pack(pop)

class Structuresults {
public:
    // 基础信息
    int num_of_scanned_blocks = 6;
    int out_range[20] = { 0 };
    ComprehensiveInfo comprehensive_info;
 
    StructuralInformation structures_attributes;

    // 诊断数据
    std::vector<Diaresults> diarelist{};

    std::vector<SectionInformation> section_attributes;
	// int max_number_of_possible_sections = 0;
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

    std::vector<ImportDescriptor> import_descriptor;

    // 崩溃报告（文件加载失败等原因未能成功分析）
	CrashReport crashreport{};
    void crash_information_set(error_category code, const std::string& msg = "");
};

int is_this_section_valid(const SectionHeader& header, SharedStructure shared_structure, Structuresults data_container);
int file_confidence_detection(SharedStructure shared_structure);