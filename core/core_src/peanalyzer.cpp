#include <fstream>
#include <cstdint>
#include <sstream>
#include <cstring>
#include <algorithm>

#include "database.h"

constexpr int BUFFER_SIZE = 5600;                      // 复用缓冲区大小
constexpr int REASONABLE_MAX_SECTIONS = 128;           // 支持的最大节区数量
constexpr int REASONABLE_MAX_IMPORT_DESCRIPTORS = 200; // 支持的最大导入描述符数量

// SharedStructure shared_structure{};

/* 普通工具函数 */
/*
	interval_relation_judgment ：两个区间的关系判断函数
	interval_insertion_sort    ：处理区间的插入排序函数
	interval_hole_scan         ：区间缺口扫描函数（要求传入参数已排序）
*/
static int interval_relation_judgment(uint64_t f_begin, uint64_t f_end, uint64_t a_begin, uint64_t a_end) { 
	// front和after的始末值
	// f_begin-前区间起始地址  f_end-前区间结束地址  a_begin-后区间起始地址  a_end-后区间结束地址
	// 所有区间的begin和end值取值为，[begin, end)，即区间结束值其实不包含end值
	// 使用时当前区间是后一个区间，遍历比较以当前区间为准，循环检测已检察过的比它小的区间
	if (a_begin > a_end) {
		return -1; // 当前区间无效
	}
	if (f_begin < a_begin && f_end == a_begin && 
		f_begin < a_end && f_end < a_end) {
		return 1; // 正常区间
	}
	else if (f_begin < a_begin && f_end > a_begin && 
		f_begin < a_end && f_end < a_end) {
		return 2; // 重叠
	}
	else if (f_begin == a_begin && f_end > a_begin && 
		f_begin < a_end && f_end == a_end){
		return 2; // 重叠
	}
	else if (f_begin < a_begin && f_end > a_begin && 
		f_begin < a_end && f_end == a_end) {
		return 2; // 重叠
	}
	else if (f_begin == a_begin && f_end > a_begin && 
		f_begin < a_end && f_end >a_end) {
		return 2; // 重叠
	}
	else if (f_begin < a_begin && f_end < a_begin && 
		f_begin < a_end && f_end < a_end) {
		return 3; // 空洞
	}
	else if (f_begin > a_begin && f_end > a_begin && 
		f_begin == a_end && f_end > a_end){
		return 4; // 乱序
	}
	else if (f_begin > a_begin && f_end > a_begin && f_begin < a_end) {
		return 5; // 重叠 + 乱序
	}
	else if (f_begin > a_begin && f_end > a_begin && 
		f_begin > a_end && f_end > a_end) {
		return 6; // 乱序空洞
	}
	else {
		// 特殊情况处理
		if (f_begin == f_end && a_begin != a_end) {
			if (f_begin == a_begin - 1) {
				return 1; // 正常
			}
			else if (f_begin >= a_begin && f_begin < a_end) {
				return 2; // 重叠
			}
			else if (f_begin < a_begin - 1) {
				return 3; // 空洞
			}
			else if (f_begin >= a_end) {
				return 4; // 乱序
			}
		}
		else if (f_begin != f_end && a_begin == a_end) {
			if (a_begin == f_end) {
				return 1; // 正常
			}
			else if (a_begin >= f_begin && a_begin < f_end) {
				return 2; // 重叠
			}
			else if (a_begin > f_end) {
				return 3; // 空洞
			}
			else if (a_begin < f_begin) {
				return 4; // 乱序
			}
		}
		else if(f_begin == f_end && a_begin == a_end) {
			if (f_begin + 1 == a_begin) {
				return 1; // 正常
			}
			else if (f_begin == a_begin) {
				return 2; // 重叠
			}
			else if (f_begin + 1 < a_begin) {
				return 3; // 空洞
			}
			else if (f_begin >= a_begin + 1) {
				return 4; // 乱序
			}
		}
		return 0; // 未知状态
	}
}

static void interval_insertion_sort(std::vector<SectionRange>& input_vector) {
	// input_vector-记录节区起始地址的数组，
	// 实际使用为Structuresults.memory_interval_table或Structuresults.storage_interval_table
	size_t n = input_vector.size();
	for (size_t i = 1; i < n; i++) {
		SectionRange current = input_vector[i];
		int64_t j = i - 1; /* 无符号整数死循环问题，已修复 */
		while (j >= 0) {
			if (current.begin < input_vector[j].begin) {
				input_vector[j + 1] = input_vector[j];
				j--;
			}
			else if (current.begin == input_vector[j].begin) {
				if (current.end < input_vector[j].end) {
					input_vector[j + 1] = input_vector[j];
					j--;
				}
				else {
					break;
				}
			}
			else {
				break;
			}
		}
		input_vector[j + 1] = current;
	}
}

static bool interval_hole_scan(const std::vector<SectionRange>& input_vector) {
	// input_vector-记录节区起始地址的数组，
	// 实际使用为Structuresults.memory_interval_table或Structuresults.storage_interval_table
	for(size_t i = 0; i < input_vector.size() - 1; i++) {
		if (input_vector[i].begin < input_vector[i + 1].begin && 
		input_vector[i].end + 0x01 < input_vector[i + 1].begin) {
			return false;
		}
	}
	return true;
}

/* private里的工具函数 */
void PEanalyzer::clear_buffer() {
	for (int i = 0; i < 256; i++) {
		mulbuffer[i] = 0;
	}
}

// FileHeader分析用辅助函数
std::string PEanalyzer::field_interpretation(uint16_t input_machine) {
	// input_machine-FileHeader中的machine值
	switch (input_machine) {
	case 0x014C: return "Intel 386 (32-bit x86)";
	case 0x8664:
		shared_structure.bitness_ = 64;
		return "AMD64 (64-bit x86)";
	case 0x01C0: return "ARM LE";
	case 0x01C4: return "ARMv7 THUMB LE";
	case 0xAA64:
		shared_structure.bitness_ = 64;
		return "ARM64 LE";
	case 0x0200:
		shared_structure.bitness_ = 64;
		return "Intel Itanium";
	case 0x0162: return "MIPS R3000";
	case 0x0166: return "MIPS R4000";
	case 0x0168: return "MIPS R10000";
	case 0x0169: return "MIPS WCE v2";
	case 0x0184:
		shared_structure.bitness_ = 64;
		return "Alpha AXP";
	case 0x01A2: return "SH3";
	case 0x01A3: return "SH3 DSP";
	case 0x01A6: return "SH4";
	case 0x01A8:
		shared_structure.bitness_ = 64;
		return "SH5";
	case 0x01C2: return "ARM Thumb-2 LE";
	case 0x01D3: return "Matsushita AM33";
	case 0x01F0: return "PowerPC";
	case 0x01F1: return "PowerPC FP";
	case 0x0266: return "MIPS16";
	case 0x0366: return "MIPS with FPU";
	case 0x0466: return "MIPS16 with FPU";
	case 0x0520: return "Tricore";
	case 0x0EBC:
		shared_structure.bitness_ = 82;
		return "EFI Byte Code";
	case 0x9041: return "M32R";
	case 0xC0EE: return "CEE";
	default: return "Unknown";
	}
}

// OptionalHeader分析用辅助函数
void PEanalyzer::magic_check(uint16_t input_magic, Diaresults& input_result, int& length) {
	switch (input_magic) {
	case 0x20B:
		shared_structure.bitness_ = 64;
		length = 238;
		input_result.information_list_.push_back(
			detailed_information(
				Core::Severity::INFO_LOW,
				"Magic",
				"_IMAGE_OPTIONAL_HEADER64",
				"The bit width is 64 bits",
				static_cast<uint64_t>(shared_structure.peheader_offset_) + 24
			)
		);
		/*input_result.informations_.push_back("【普通】位宽：64位");*/
		break;
	case 0x10B:
		shared_structure.bitness_ = 32;
		length = 222;
		input_result.information_list_.push_back(
			detailed_information(
				Core::Severity::INFO_LOW,
				"Magic",
				"_IMAGE_OPTIONAL_HEADER32",
				"The bit width is 32 bits",
				static_cast<uint64_t>(shared_structure.peheader_offset_) + 24
			)
		);
		/*input_result.informations_.push_back("【普通】位宽：32位");*/
		break;
	case 0x107:
		shared_structure.bitness_ = 82;
		length = 110;
		input_result.information_list_.push_back(
			detailed_information(
				Core::Severity::INFO_LOW,
				"Magic",
				"_IMAGE_OPTIONAL_HEADER",
				"ROM file",
				static_cast<uint64_t>(shared_structure.peheader_offset_) + 24
			)
		);
		/*input_result.informations_.push_back("【普通】位宽：ROM映像");*/
		break;
	default:
		/*inputresult.informations_.push_back("【异常】magic（魔术字）无匹配值，未知架构。");
		inputresult.warnings_.push_back("magic 字段无效或未知架构。");
		inputresult.field_anomalies_.push_back("magic 字段匹配失败。");*/
		break;
	}
}

void PEanalyzer::magic_joint_check() {
	/* 暂定区域，实现magic字段相关的一致性验证 */
}

void PEanalyzer::magic_joint_judge() {
	/* 暂定区域，实现magic字段错误时的预验证和反推 */
	/* 包括以下字段：machine、sizeofoptionalheader、datadirectory、imageBase、sectionalignment、filealignment、subsystem、characteristics、addressofentrypoint */
	/* 包括的验证方式：越界验证、节归属验证、对齐验证、编译器模式匹配等 */
}

// SectionHeader分析用辅助函数 
void PEanalyzer::section_characteristic_judge(uint32_t input_characteristic, Structuresults& data_container) {
	if (data_container.section_attributes.empty()) {
		return;
	}
	data_container.section_attributes.back().mem_execute_ = ((input_characteristic & 0x20000000) != 0);
	data_container.section_attributes.back().mem_read_ = ((input_characteristic & 0x40000000) != 0);
	data_container.section_attributes.back().mem_write_ = ((input_characteristic & 0x80000000) != 0);
	data_container.section_attributes.back().mem_shared_ = ((input_characteristic & 0x10000000) != 0);
	data_container.section_attributes.back().cnt_code_ = ((input_characteristic & 0x00000020) != 0);
	data_container.section_attributes.back().cnt_initialized_data_ = ((input_characteristic & 0x00000040) != 0);
	data_container.section_attributes.back().cnt_uninitialized_data_ = ((input_characteristic & 0x00000080) != 0);
}

void PEanalyzer::section_characteristic_check(uint32_t input_characteristic, Diaresults& inputresult, size_t num, Structuresults& data_container) {
	std::string msg = "";
	uint64_t characteristics_offset = 
		static_cast<uint64_t>(inputresult.file_offset_) + 0x28 + static_cast<uint64_t>(num) * 40 + 36; // Characteristics字段偏移，其中num值被限制在128内，不会导致溢出
	// mem_execute_ + mem_write_
	if (data_container.section_attributes[num].mem_execute_ && data_container.section_attributes[num].mem_write_) {
		// 异常：节区属性可读 + 可写，存在安全风险
		msg = "The attribute is readable and writable, posing a security risk.";
		inputresult.information_list_.push_back(
			indexed_issue(
				Core::Severity::WARNING_MED,
				"Section Header",
				num,
				msg,
				characteristics_offset
			)
		);
	}
	// mem_shared_ + cnt_uninitialized_data_
	if (data_container.section_attributes[num].mem_shared_ && data_container.section_attributes[num].cnt_uninitialized_data_) {
		// 可疑：节区存在共享零数据，注意特殊处理
		msg = "The attribute is shared and contains uninitialized data, which may require special handling.";
		inputresult.information_list_.push_back(
			indexed_issue(
				Core::Severity::SUSPICIOUS,
				"Section Header",
				num,
				msg,
				characteristics_offset
			)
		);
	}
	// mem_write_ + !mem_read_
	if (data_container.section_attributes[num].mem_write_ && !data_container.section_attributes[num].mem_read_) {
		// 异常：节区属性可执行 + 不可读，无法正常执行
		msg = "Attribute executable but not readable, cannot execute normally";
		inputresult.information_list_.push_back(
			indexed_issue(
				Core::Severity::WARNING_MED,
				"Section Header",
				num,
				msg,
				characteristics_offset
			)
		);
	}
	// mem_execute_ + !mem_read_
	if (data_container.section_attributes[num].mem_execute_ && !data_container.section_attributes[num].mem_read_) {
		// 可疑：节区属性只写内存，非常见情况。
		msg = "The attribute is write-only memory, which is uncommon";
		inputresult.information_list_.push_back(
			indexed_issue(
				Core::Severity::SUSPICIOUS,
				"Section Header",
				num,
				msg,
				characteristics_offset
			)
		);
	}
	// !mem_read_ + !mem_write_ + !mem_execute_
	if (!data_container.section_attributes[num].mem_execute_ && !data_container.section_attributes[num].mem_read_ && !data_container.section_attributes[num].mem_write_) {
		// 异常：节区属性不可执行 + 不可读 + 不可写，无法正常访问
		msg = "The property is not executable, not readable, not writable, and cannot be accessed normally";
		inputresult.information_list_.push_back(
			indexed_issue(
				Core::Severity::WARNING_MED,
				"Section Header",
				num,
				msg,
				characteristics_offset
			)
		);
	}
	// 6. cnt_code_ + cnt_uninitialized_data_
	if (data_container.section_attributes[num].cnt_code_ && data_container.section_attributes[num].cnt_uninitialized_data_) {
		// 异常：属性包含可执行代码又包含未初始化数据，矛盾属性无法正常访问
		msg = "Contains both executable code and uninitialised data";
		inputresult.information_list_.push_back(
			indexed_issue(
				Core::Severity::WARNING_MED,
				"Section Header",
				num,
				msg,
				characteristics_offset
			)
		);
	}
	// 7. cnt_initialized_data_ + cnt_uninitialized_data_
	if (data_container.section_attributes[num].cnt_initialized_data_ && data_container.section_attributes[num].cnt_uninitialized_data_) {
		// 异常：属性包含已初始化数据又包含未初始化数据，矛盾属性无法正常访问
		msg = "Contains both initialised and uninitialised data";
		inputresult.information_list_.push_back(
			indexed_issue(
				Core::Severity::WARNING_MED,
				"Section Header",
				num,
				msg,
				characteristics_offset
			)
		);
	}
}

int PEanalyzer::section_name_match(const uint8_t input_name[8]) {
	struct NameCompare {
		const uint8_t name[8];
		int id;
	};

	// 其实最后那个比如8469就是每个情况的前面两个字母的ASCII值
	static constexpr NameCompare SECTION_TABLE[] = {
		{{0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00}, 8469},    // .text
		{{0x2E, 0x63, 0x6F, 0x64, 0x65, 0x00, 0x00, 0x00}, 6779},    // .code
		{{0x2E, 0x69, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00}, 7384},    // .itext
		{{0x2E, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00}, 6865},    // .data
		{{0x2E, 0x72, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00}, 8268},    // .rdata
		{{0x2E, 0x69, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00}, 7368},    // .idata
		{{0x2E, 0x65, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00}, 6968},    // .edata
		{{0x2E, 0x62, 0x73, 0x73, 0x00, 0x00, 0x00, 0x00}, 6683},    // .bss
		{{0x2E, 0x72, 0x73, 0x72, 0x63, 0x00, 0x00, 0x00}, 8283},    // .rsrc
		{{0x2E, 0x72, 0x65, 0x6C, 0x6F, 0x63, 0x00, 0x00}, 8269},    // .reloc
		{{0x2E, 0x64, 0x65, 0x62, 0x75, 0x67, 0x24, 0x53}, 6869},    // .debug$S
		{{0x2E, 0x64, 0x72, 0x65, 0x63, 0x74, 0x76, 0x65}, 6882},    // .drectve
		{{0x2E, 0x74, 0x6C, 0x73, 0x00, 0x00, 0x00, 0x00}, 8476},    // .tls
		{{0x2E, 0x70, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00}, 8068},    // .pdata
		{{0x2E, 0x78, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00}, 8868}     // .xdata
	};

	auto it = std::find_if(std::begin(SECTION_TABLE), std::end(SECTION_TABLE),
		[input_name](const NameCompare& entry) {
			return memcmp(input_name, entry.name, 8) == 0;
		});

	if (it != std::end(SECTION_TABLE)) {
		return it->id;
	}
	return -1;
}

void PEanalyzer::section_name_check(const uint8_t input_name[8], const uint32_t input_characteristic, Diaresults& inputresult, size_t num, Structuresults& data_container) {
	/*
	[0] bool mem_execute_;               // 内存可执行
    [1] bool mem_read_;                  // 内存可读
    [2] bool mem_write_;                 // 内存可写
    [3] bool mem_shared_;                // 内存共享
    [4] bool cnt_code_;                  // 包含可执行代码 
    [5] bool cnt_initialized_data_;      // 包含已初始化数据
    [6] bool cnt_uninitialized_data_;    // 零初始化
	*/
	bool judgement_set[7] = {0};
	bool actual_val[7] = {};
	bool is_attribute_common = true;
	int name_id = section_name_match(input_name);
	
	// .text .code .itext
	if (name_id == 8469 || name_id == 6779 || name_id == 7384) { 
		judgement_set[0] = true;
		judgement_set[1] = true;
		judgement_set[2] = false;
		judgement_set[4] = true;
		if (input_characteristic != 0x60000020) { is_attribute_common = false; }
	}
	// .data
	else if (name_id == 6865) {
		judgement_set[0] = false;
		judgement_set[1] = true;
		judgement_set[2] = true;
		judgement_set[5] = true;
		if (input_characteristic != 0xC0000040) { is_attribute_common = false; }
	}
	// .rdata .idata .edata
	else if (name_id == 8268 || name_id == 7368 || name_id == 6968) {
		judgement_set[0] = false;
		judgement_set[1] = true;
		judgement_set[2] = false;
		judgement_set[5] = true;
		if (input_characteristic != 0x40000040) { is_attribute_common = false; }
	}
	// .bss
	else if (name_id == 6683) {
		judgement_set[0] = false;
		judgement_set[1] = true;
		judgement_set[2] = true;
		judgement_set[6] = true;
		if (input_characteristic != 0xC0000080) { is_attribute_common = false; }
	}
	// .rsrc
	else if (name_id == 8283) {
		judgement_set[0] = false;
		judgement_set[1] = true;
		judgement_set[2] = false;
		judgement_set[5] = true;
		if (input_characteristic != 0x40000040) { is_attribute_common = false; }
	}
	// .reloc
	else if (name_id == 8269) {
		judgement_set[0] = false;
		judgement_set[1] = true;
		judgement_set[2] = false;
		judgement_set[5] = true;
		if (input_characteristic != 0x42000040 
			&& input_characteristic != 0x40000040) { is_attribute_common = false; }
	}
	// .debug$S .drectve
	else if (name_id == 6869 || name_id == 6882) {
		judgement_set[0] = false;
		judgement_set[1] = true;
		judgement_set[2] = false;
		judgement_set[5] = true;
		if (input_characteristic != 0x42100040 
			&& input_characteristic != 0x40100040) { is_attribute_common = false; }
	}
	// .tls
	else if (name_id == 8476) {
		judgement_set[0] = false;
		judgement_set[1] = true;
		judgement_set[2] = true;
		judgement_set[5] = true;
		if (input_characteristic != 0xC0000040) { is_attribute_common = false; }
	}
	// .pdata .xdata
	else if (name_id == 8068 || name_id == 8868) {
		judgement_set[0] = false;
		judgement_set[1] = true;
		judgement_set[2] = false;
		judgement_set[5] = true;
		if (input_characteristic != 0x40000040) { is_attribute_common = false; }
	}
	else {
		// 可疑：节区名称非常见编译器生成，无法判断其属性合法性，注意分析结果的可靠性。
		inputresult.information_list_.push_back(
			detailed_information(
				Core::Severity::SUSPICIOUS,
				"name",
				"Section Header",
				"Results compiled by uncommon compilers.",
				inputresult.file_offset_
			)
		);
		return;
	}

	actual_val[0] = data_container.section_attributes[num].mem_execute_;
	actual_val[1] = data_container.section_attributes[num].mem_read_;
	actual_val[2] = data_container.section_attributes[num].mem_write_;
	actual_val[3] = data_container.section_attributes[num].mem_shared_;
	actual_val[4] = data_container.section_attributes[num].cnt_code_;
	actual_val[5] = data_container.section_attributes[num].cnt_initialized_data_;
	actual_val[6] = data_container.section_attributes[num].cnt_uninitialized_data_;

	if (memcmp(judgement_set, actual_val, 7)) {
		// 可疑：节区名称与其期望的权限不匹配，可能存在伪装的节区，注意分析结果的可靠性。
		inputresult.information_list_.push_back(
			detailed_information(
				Core::Severity::SUSPICIOUS,
				"name",
				"Section Header",
				"The value of 'name' does not match the expected permissions.",
				inputresult.file_offset_
			)
		);
	}
	if (!is_attribute_common) {
		// 可疑：节区名称与其期望的权限不匹配，可能存在伪装的节区，注意分析结果的可靠性。
		inputresult.information_list_.push_back(
			detailed_information(
				Core::Severity::SUSPICIOUS,
				"characteristic",
				"Section Header",
				"The value of 'characteristic' is uncommon.",
				inputresult.file_offset_
			)
		);
	}
	else {
		data_container.section_attributes[num].known_combination_ = true;
	}
}

/* public函数 */
bool PEanalyzer::dosheader_analysis(Structuresults& data_container) {
	/* 可能的作用域问题 */
	// shared_structure = SharedStructure();
	/* 不要动 */

	clear_buffer();
	Diaresults result;
	pedata_.seekg(0, std::ios::beg);
	if (!pedata_) {
		data_container.crash_imformation_set(
			// 文件流异常，文件指针移动失败，可能文件未正确打开或已损坏。
			error_category::FILE_SEEK_FAILED,
			"DOS Header: File stream exception, \
			failed to move file pointer, \n\
			the file may not have been opened correctly or is corrupted."
		);
		data_container.diarelist.push_back(result);
		return false;
	}
	pedata_.read(reinterpret_cast<char*>(mulbuffer), 64);
	if (pedata_.gcount() != 64) {
		data_container.crash_imformation_set(
			// 文件流读取数据到内存缓冲区失败。
			error_category::FILE_READ_FAILED,
			"DOS Header: Failed to read data from the file stream into the memory buffer."
		);
		data_container.diarelist.push_back(result);
		return false;
	}

	result.component_name_ = "IMAGE_DOS_HEADER";
	result.file_offset_ = 0;
	result.data_size_ = 64;

	std::memcpy(&data_container.dosheader, mulbuffer, sizeof(DOSHeader));
	shared_structure.peheader_offset_ = mulbuffer[60] | (mulbuffer[61] << 8) | (mulbuffer[62] << 16) | (mulbuffer[63] << 24);
	// 异常：不合法的MZ签名
	if (mulbuffer[0] != 'M' || mulbuffer[1] != 'Z') {
		data_container.dosheader.e_magic = (mulbuffer[0] << 8) | mulbuffer[1];
		data_container.structures_attributes.dos_header_normal_ = false;
		result.information_list_.push_back(
			invalid_value(
				Core::Severity::ERROR_HIGH,
				"e_magic",
				"DOS Header",
				data_container.dosheader.e_magic,
				0,
				true
			)
		);
	}

	if (data_container.dosheader.e_lfanew < 0x40 && data_container.dosheader.e_lfanew > 0) {
		int start_index = data_container.dosheader.e_lfanew;
		int copy_length = 0x40 - data_container.dosheader.e_lfanew;

		data_container.overlapping_area.emplace_back();
		auto& item = data_container.overlapping_area.back();
		item.overlapping_data.assign(mulbuffer + start_index,
			mulbuffer + start_index + copy_length);
		item.length = copy_length;
		item.expectation_offset = 0;
		item.actual_offset = 0;

		data_container.overlapping_area.back().length = copy_length;
		data_container.overlapping_area.back().expectation_offset = 0x40;
		data_container.overlapping_area.back().actual_offset = data_container.dosheader.e_lfanew;
	}

	data_container.diarelist.push_back(result);
	data_container.out_range_[0] = 1;
	return true;
}

bool PEanalyzer::dosstub_analysis(Structuresults& data_container) {
	clear_buffer();
	Diaresults result;
	uint8_t reading_mode = 0; /* 读取方式 0-正常读取，1-分段读取，2-不读取 */
	uint8_t imformation_processing_mode = 1; /* 信息处理方式 1-需要异常 0-不需要异常 */

	pedata_.seekg(64, std::ios::beg);
	if (!pedata_) {
		data_container.crash_imformation_set(
			// 文件流异常，文件指针移动失败，可能文件未正确打开或已损坏。
			error_category::FILE_SEEK_FAILED,
			"DOS Stub: File stream exception, \
			failed to move file pointer, \n\
			the file may not have been opened correctly or is corrupted."
		);
		data_container.diarelist.push_back(result);
		return false;
	}

	// 这里有无符号整数的坑，已修复
	int count = shared_structure.peheader_offset_ > 64 ? shared_structure.peheader_offset_ - 64 : 0;

	result.component_name_ = "DOS Stub";
	result.file_offset_ = 64;
	result.data_size_ = count;

	if (count == 0) {
		data_container.structures_attributes.dos_stub_exist_ = false;
		imformation_processing_mode = 0;
		result.information_list_.push_back(
			structure_missing(
				Core::Severity::SUSPICIOUS,
				"DOS Stub"
			)
		);
	}
	else if (count <= 80) {  // 1~80
		result.additional_information.push_back("DOS Stub is relatively short.");
	}
	else if (count <= 256) { // 81~256
		imformation_processing_mode = 0;
	}
	else{
		if(count > BUFFER_SIZE && count <= 10240){
			reading_mode = 1;
		}
		else if(count > 10240){
			reading_mode = 2;
		}
		data_container.structures_attributes.dos_stub_normal_ = false;
		result.information_list_.push_back(
			abnormal_length(
				Core::Severity::SUSPICIOUS,
				"DOS Stub",
				count,
				64
			)
		);
		result.issuspicious = true;
	}
	
	// 读取方式处理
	int num_of_bytes_read = BUFFER_SIZE;
	int num_of_bytes_remaining = count - BUFFER_SIZE;
	switch (reading_mode) {
	case 0:  // 正常读取
		pedata_.read(reinterpret_cast<char*>(mulbuffer), count);
		if (pedata_.gcount() != count) {
			data_container.crash_imformation_set(
				// 文件流读取数据到内存缓冲区失败。
				error_category::FILE_READ_FAILED,
				"DOS Stub: Failed to read data from the file stream into the memory buffer."
			);
			data_container.diarelist.push_back(result);
			return false;
		}
		for (size_t i = 0; i < count; i++) {
			data_container.dosstub.push_back(mulbuffer[i]);
		}
		break;
	case 1:  // 分段读取
		while (num_of_bytes_read > 0) {
			pedata_.read(reinterpret_cast<char*>(mulbuffer), num_of_bytes_read);
			if (pedata_.gcount() != count) {
				data_container.crash_imformation_set(
					// 文件流读取数据到内存缓冲区失败。
					error_category::FILE_READ_FAILED,
					"DOS Stub: Failed to read data from the file stream into the memory buffer."
				);
				data_container.diarelist.push_back(result);
				return false;
			}
			num_of_bytes_read = (num_of_bytes_remaining - num_of_bytes_read > BUFFER_SIZE) ? BUFFER_SIZE : (num_of_bytes_remaining - num_of_bytes_read);
			num_of_bytes_remaining -= num_of_bytes_read;
		}
		for (size_t i = 0; i < count; i++) {
			data_container.dosstub.push_back(mulbuffer[i]);
		}
		break;
	case 2:  // 不读取
		pedata_.seekg(static_cast<std::streamoff>(64) + count, std::ios::beg);
		if (!pedata_) {
			data_container.crash_imformation_set(
				// 文件流异常，文件指针移动失败，可能文件未正确打开或已损坏。
				error_category::FILE_READ_FAILED,
				"DOS Stub: File stream exception, \
				failed to move file pointer, \n\
				the file may not have been opened correctly or is corrupted."
			);
			data_container.diarelist.push_back(result);
			return false;
		}
		break;
	default: // 异常
		data_container.crash_imformation_set(
			error_category::LOGIC_ERROR,
			"An unknown parameter appeared while analysing the DOS Stub area."
			// 分析 DOS Stub 区域时出现未知参数。
		);
		throw std::runtime_error("An unknown parameter appeared while analysing the DOS Stub area.");
		break;
	}
	
	// 信息处理
	switch (imformation_processing_mode) {
	case 0:
		data_container.diarelist.push_back(result);
		break;
	case 1:
		data_container.structures_attributes.dos_stub_normal_ = false;
		result.information_list_.push_back(
			abnormal_length(
				Core::Severity::SUSPICIOUS,
				"DOS Stub",
				count,
				64
			)
		);
		result.issuspicious = true;
		data_container.diarelist.push_back(result);
		break;
	default:
		throw std::runtime_error("An unknown parameter appeared while analysing the DOS Stub area.");
		break;
	}
	
	data_container.out_range_[1] = 1;
	return true;
}

bool PEanalyzer::file_header_analysis(Structuresults& data_container) {
	clear_buffer();
	Diaresults result;

	if (!pedata_.good()) {
		data_container.crash_imformation_set(
			// 文件流异常，文件指针移动失败，可能文件未正确打开或已损坏。
			error_category::FILE_SEEK_FAILED,
			"File Header: File stream exception, \
			failed to move file pointer, \n\
			the file may not have been opened correctly or is corrupted."
		);
		data_container.diarelist.push_back(result);
		return false;
	}
	if (!data_container.overlapping_area.empty() &&
		data_container.overlapping_area.back().actual_offset < 0x40) {
		memcpy(mulbuffer, 
			data_container.overlapping_area.back().overlapping_data.data(), 
			data_container.overlapping_area.back().overlapping_data.size());
		pedata_.read(reinterpret_cast<char*>(mulbuffer + data_container.overlapping_area.back().overlapping_data.size()),
			BUFFER_SIZE - data_container.overlapping_area.back().overlapping_data.size());
		if (pedata_.gcount() != BUFFER_SIZE - data_container.overlapping_area.back().overlapping_data.size()) {
			data_container.crash_imformation_set(
				// 文件流读取数据到内存缓冲区失败。
				error_category::FILE_READ_FAILED,
				"File Header: Failed to read data from the file stream into the memory buffer."
			);
			data_container.diarelist.push_back(result);
			return false;
		}
	}
	else {
		pedata_.read(reinterpret_cast<char*>(mulbuffer), BUFFER_SIZE);
		if (pedata_.gcount() != BUFFER_SIZE) {
			data_container.crash_imformation_set(
				// 文件流读取数据到内存缓冲区失败。
				error_category::FILE_READ_FAILED,
				"File Header: Failed to read data from the file stream into the memory buffer."
			);
			data_container.diarelist.push_back(result);
			return false;
		}
	}

	result.component_name_ = "IMAGE_FILE_HEADER";
	result.file_offset_ = shared_structure.peheader_offset_;
	result.data_size_ = 24; // 这里长度加上了PE签名的4字节

	read_offset += 24;

	std::memcpy(&data_container.fileheader, mulbuffer, sizeof(FileHeader));
	// shared_structure.machine_ = data_container.fileheader.machine;
	// shared_structure.number_of_sections_ = data_container.fileheader.numberofsections;
	// shared_structure.size_of_optionalheader_ = data_container.fileheader.sizeofoptionalheader;

	// 异常：不合法的PE签名
	if (mulbuffer[0] != 'P' || mulbuffer[1] != 'E' || mulbuffer[2] != '\0' || mulbuffer[3] != '\0') {
		data_container.fileheader.signature = (mulbuffer[0] << 24) | (mulbuffer[1] << 16) | (mulbuffer[2] << 8) | mulbuffer[3];
		result.isvalid = false;
		result.issuspicious = true;
		result.information_list_.push_back(
			invalid_value(
				Core::Severity::ERROR_HIGH,
				"signature",
				"NT Header",
				data_container.fileheader.signature,
				shared_structure.peheader_offset_,
				true
			)
		);
	}
	
	/* 偏移检查 */
	// 异常：File Header偏移异常，期望偏移值大于0x40
	if (shared_structure.peheader_offset_ < 0x40) {
		data_container.structures_attributes.file_header_normal_ = false;
		result.information_list_.push_back(
			excursion_anomaly(
				Core::Severity::WARNING_MED,
				"e_lfanew",
				"DOS Header",
				data_container.dosheader.e_lfanew
			)
		);
		result.information_list_.back().info2 = "File Header's offset is overlapping.";
	}
	
	/* 架构字段检查 */
	// 异常：machine字段为0
	if (data_container.fileheader.machine == 0x0000) {
		data_container.structures_attributes.file_header_normal_ = false;
		result.information_list_.push_back(
			invalid_value(
				Core::Severity::WARNING_MED,
				"machine",
				"File Header",
				data_container.fileheader.machine,
				static_cast<uint64_t>(data_container.dosheader.e_lfanew) + 4,
				false
			)
		);
	}
	else {
		std::string msg = field_interpretation(data_container.fileheader.machine);
		data_container.comprehensive_info_.architecture_ = msg;
		// 普通信息：machine值可与常见值匹配，具体见field_interpretation()函数
		if (msg != "Unknown") {
			result.information_list_.push_back(
				detailed_information(
					Core::Severity::INFO_LOW,
					"machine",
					"File Header",
					("Machine architecture : " + msg),
					static_cast<uint64_t>(data_container.dosheader.e_lfanew) + 4
				)
			);
		}
		// 可疑：machine非常见值
		else {
			result.information_list_.push_back(
				invalid_value(
					Core::Severity::SUSPICIOUS,
					"machine",
					"File Header",
					data_container.fileheader.machine,
					static_cast<uint64_t>(data_container.dosheader.e_lfanew) + 4,
					false
				)
			);
			result.information_list_.back().info2 = "Unknown Machine type.";
		}
	}
	
	/* 节区数量字段检查，实际数量检查的对照手段在函数 section_headers_analisis() 中 */
	// 异常：numberofsections值为0，即逻辑节区数量为0
	if (data_container.fileheader.numberofsections == 0) {
		// shared_structure.number_of_sections_isvalid_ = EleCorrectness::not_valid;
		data_container.structures_attributes.file_header_normal_ = false;
		result.information_list_.push_back(
			value_mismatch(
				Core::Severity::WARNING_MED,
				"NumberOfSections",
				"File Header",
				5,
				data_container.fileheader.numberofsections,
				static_cast<uint64_t>(shared_structure.peheader_offset_) + 6
			)
		);
	}
	// 可疑：numberofsections值过大
	else if (data_container.fileheader.numberofsections > 96) {
		// shared_structure.number_of_sections_isvalid_ = EleCorrectness::uncertain;
		data_container.structures_attributes.file_header_normal_ = false;
		result.information_list_.push_back(
			value_mismatch(
				Core::Severity::SUSPICIOUS,
				"NumberOfSections",
				"File Header",
				5,
				data_container.fileheader.numberofsections,
				static_cast<uint64_t>(shared_structure.peheader_offset_) + 6
			)
		);
	}

	/* sizeofoptionalheader字段检查 */
	// 异常：sizeofoptionalheader非常见标准值
	if (data_container.fileheader.sizeofoptionalheader != 0xF0 && data_container.fileheader.sizeofoptionalheader != 0xE0) {
		data_container.structures_attributes.file_header_normal_ = false;
		result.information_list_.push_back(
			invalid_value(
				Core::Severity::WARNING_MED,
				"SizeOfOptionalHeader",
				"File Header",
				data_container.fileheader.sizeofoptionalheader,
				static_cast<uint64_t>(shared_structure.peheader_offset_) + 20,
				false
			)
		);
	}

	data_container.diarelist.push_back(result);
	data_container.out_range_[2] = 1;
	return true;
}

bool PEanalyzer::optional_header_analysis(Structuresults& data_container) {
	Diaresults result;
	int headerlength = data_container.fileheader.sizeofoptionalheader;

	shared_structure.magic_ = (mulbuffer[read_offset] << 8) | mulbuffer[read_offset + 1];
	/* 架构确定、magic字段验证 */
	PEanalyzer::magic_check(shared_structure.magic_, result, headerlength);
	result.component_name_ = "IMAGE_OPTIONAL_HEADER";
	result.file_offset_ = shared_structure.peheader_offset_ + 24;
	result.data_size_ = headerlength;

	data_container.structures_attributes.head_end_address_ = result.file_offset_ + result.data_size_;

	/* 分类填充、imagebase值判断 */
	// 32位
	if (shared_structure.bitness_ == 32) { 
		if (read_offset >= 0 && read_offset < BUFFER_SIZE) {
			std::memcpy(&data_container.optionalheader32,
				mulbuffer + read_offset,
				sizeof(OptionalHeader32));
			read_offset = read_offset + data_container.fileheader.sizeofoptionalheader;
		}
		
		shared_structure.address_of_entrypoint_ = data_container.optionalheader32.AddressOfEntryPoint;
		shared_structure.imagebase32_ = data_container.optionalheader32.ImageBase;
		shared_structure.section_alignment_ = data_container.optionalheader32.SectionAlignment;
		shared_structure.file_alignment_ = data_container.optionalheader32.FileAlignment;
		shared_structure.size_of_image_ = data_container.optionalheader32.SizeOfImage;
		shared_structure.import_table_RVA_ = data_container.optionalheader32.DataDirectory_[1].VirtualAddress;
		shared_structure.import_table_size_ = data_container.optionalheader32.DataDirectory_[1].Size;
		shared_structure.relocation_table_RVA_ = data_container.optionalheader32.DataDirectory_[5].VirtualAddress;
		shared_structure.relocation_table_size_ = data_container.optionalheader32.DataDirectory_[5].Size;
		shared_structure.tls_table_RVA_ = data_container.optionalheader32.DataDirectory_[9].VirtualAddress;
		shared_structure.tls_table_size_ = data_container.optionalheader32.DataDirectory_[9].Size;

		shared_structure.size_of_headers_ = data_container.optionalheader32.SizeOfHeaders;

		// data_container.file_identification_ = "32位";
		data_container.comprehensive_info_.file_identification_ = "32位";

		// 异常：imagebase字段为0
		if (shared_structure.imagebase32_ == 0) {
			shared_structure.image_base_isvalid_ = EleCorrectness::not_valid;
			data_container.structures_attributes.optional_header_normal_ = false;
			result.information_list_.push_back(
				invalid_value(
					Core::Severity::WARNING_MED,
					"ImageBase",
					"Optional Header",
					shared_structure.imagebase32_,
					static_cast<uint64_t>(shared_structure.peheader_offset_) + 24 + 28,
					false
				)
			);
		}
		// 异常：imagebase预设地址超过32位空间地址上限
		else if (shared_structure.imagebase32_ >= 0xFFFFFFFF) {
			shared_structure.image_base_isvalid_ = EleCorrectness::not_valid;
			data_container.structures_attributes.optional_header_normal_ = false;
			result.information_list_.push_back(
				address_out_of_range(
					Core::Severity::WARNING_MED,
					"ImageBase",
					"Optional Header",
					shared_structure.imagebase32_
				)
			);
		}
	}
	// 64位
	else if (shared_structure.bitness_ == 64) { 
		if (read_offset >= 0 && read_offset < BUFFER_SIZE) {
			std::memcpy(&data_container.optionalheader64,
				mulbuffer + read_offset,
				sizeof(OptionalHeader64));
			read_offset = read_offset + data_container.fileheader.sizeofoptionalheader;
		}
		
		shared_structure.address_of_entrypoint_ = data_container.optionalheader64.AddressOfEntryPoint;
		shared_structure.imagebase64_ = data_container.optionalheader64.ImageBase;
		shared_structure.section_alignment_ = data_container.optionalheader64.SectionAlignment;
		shared_structure.file_alignment_ = data_container.optionalheader64.FileAlignment;
		shared_structure.size_of_image_ = data_container.optionalheader64.SizeOfImage;
		shared_structure.import_table_RVA_ = data_container.optionalheader64.DataDirectory_[1].VirtualAddress;
		shared_structure.import_table_size_ = data_container.optionalheader64.DataDirectory_[1].Size;
		shared_structure.relocation_table_RVA_ = data_container.optionalheader64.DataDirectory_[5].VirtualAddress;
		shared_structure.relocation_table_size_ = data_container.optionalheader64.DataDirectory_[5].Size;
		shared_structure.tls_table_RVA_ = data_container.optionalheader64.DataDirectory_[9].VirtualAddress;
		shared_structure.tls_table_size_ = data_container.optionalheader64.DataDirectory_[9].Size;

		shared_structure.size_of_headers_ = data_container.optionalheader64.SizeOfHeaders;

		data_container.comprehensive_info_.file_identification_ = "64位";

		// 异常：imagebase预设地址超过64位地址上限
		if (shared_structure.imagebase64_ <= 0x100000 || 
		shared_structure.imagebase64_ >= 0x7FFF00000000) {
			shared_structure.image_base_isvalid_ = EleCorrectness::not_valid;
			data_container.structures_attributes.optional_header_normal_ = false;
			result.information_list_.push_back(
				address_out_of_range(
					Core::Severity::WARNING_MED,
					"Optional Header",
					"ImageBase",
					shared_structure.imagebase64_
				)
			);
		}
	}
	// ROM
	else if (shared_structure.bitness_ == 82) { 
		data_container.crash_imformation_set(
			error_category::UNKNOWN_ERROR,
			"Optional Header :File analysis of ROM architecture is not supported yet, please stay tuned for future updates!"
		);
		return false;

		if (read_offset >= 0 && read_offset < BUFFER_SIZE) {
			std::memcpy(&data_container.optionalheaderrom,
				mulbuffer + read_offset,
				sizeof(ROM_OptionalHeader));
			read_offset += data_container.fileheader.sizeofoptionalheader;
		}
		
		shared_structure.address_of_entrypoint_ = data_container.optionalheaderrom.AddressOfEntryPoint;
		shared_structure.base_of_code_ = data_container.optionalheaderrom.BaseOfCode;
		shared_structure.base_of_data_ = data_container.optionalheaderrom.BaseOfData;
		shared_structure.base_of_bss_ = data_container.optionalheaderrom.BaseOfBss;
		shared_structure.size_of_code_ = data_container.optionalheaderrom.SizeOfCode;
		shared_structure.size_of_initialized_data_ = data_container.optionalheaderrom.SizeOfInitializedData;
		shared_structure.size_of_uninitialized_data_ = data_container.optionalheaderrom.SizeOfUninitializedData;

		data_container.comprehensive_info_.file_identification_ = "ROM";
		/* 暂定区域，ROM架构的字段处理 */
	}
	else {
		/* 暂定区域，实现magic字段检查失败时的处理，大致包括magic字段反推和预处理 */
		/* 可能关联的部分特殊函数和变量：joint_judge_magic()，shared_structure.advbitness_，shared_structure.bitness_ */
		shared_structure.bitness_ = 0;
		data_container.crash_imformation_set(
			error_category::UNKNOWN_ERROR,
			"Optional Header :Exception handling for magic fields is not supported yet, so stay tuned for future updates!"
		);
		return false;
	}

	/* x32、x64架构剩余字段处理 */
	if (shared_structure.bitness_ == 32 || shared_structure.bitness_ == 64) {
		/* magic字段一致性检验 */
		if (shared_structure.magic_isvalid_ == EleCorrectness::valid) {
			/* 暂定区域，magic字段的一致性检验 */
			/* 可能关联的部分特殊函数和变量：magic_joint_check() */
		}

		/* file_alignment值检验 */
		// 可疑：filealignment非常见值0x200
		if (shared_structure.file_alignment_ != 0x200) {
			if (shared_structure.file_alignment_ != 0 &&
			((shared_structure.file_alignment_ & (shared_structure.file_alignment_ - 1)) == 0)) {
				data_container.structures_attributes.optional_header_normal_ = false;
				result.information_list_.push_back(
					value_mismatch(
						Core::Severity::SUSPICIOUS,
						"FileAlignment",
						"Optional Header",
						0x200,
						shared_structure.file_alignment_,
						static_cast<uint64_t>(shared_structure.peheader_offset_) + 24 + 32
					)
				);
			}
			// 异常：filealignment非合法值
			else {
				shared_structure.file_alignment_isvalid_ = EleCorrectness::not_valid;
				data_container.structures_attributes.optional_header_normal_ = false;
				result.information_list_.push_back(
					invalid_value(
						Core::Severity::WARNING_MED,
						"FileAlignment",
						"Optional Header",
						shared_structure.file_alignment_,
						static_cast<uint64_t>(shared_structure.peheader_offset_) + 24 + 36,
						false
					)
				);
			}
		}

		/* section_alignment值检验 */
		// 可疑：sectionalignment非常见值0x1000
		if (shared_structure.section_alignment_ != 0x1000) {
			if (shared_structure.section_alignment_ != 0 && 
			((shared_structure.section_alignment_ & (shared_structure.section_alignment_ - 1)) == 0)) {
				data_container.structures_attributes.optional_header_normal_ = false;
				result.information_list_.push_back(
					value_mismatch(
						Core::Severity::SUSPICIOUS,
						"SectionAlignment",
						"Optional Header",
						0x1000,
						shared_structure.section_alignment_,
						static_cast<uint64_t>(shared_structure.peheader_offset_) + 24 + 32
					)
				);
			}
			// 异常：sectionalignment非合法值
			else {
				shared_structure.section_alignment_isvalid_ = EleCorrectness::not_valid;
				data_container.structures_attributes.optional_header_normal_ = false;
				result.information_list_.push_back(
					invalid_value(
						Core::Severity::WARNING_MED,
						"Section Alignment",
						"Optional Header",
						shared_structure.section_alignment_,
						static_cast<uint64_t>(shared_structure.peheader_offset_) + 24 + 32,
						false
					)
				);
			}
		}

		/* file_alignment、section_alignment联合检验 */
		if (shared_structure.file_alignment_isvalid_ == EleCorrectness::valid && 
		shared_structure.section_alignment_isvalid_ == EleCorrectness::valid) {
			// 异常：sectionalignment < filealignment，不符合规范要求
			if (shared_structure.section_alignment_ < shared_structure.file_alignment_) {
				shared_structure.file_alignment_isvalid_ = EleCorrectness::not_valid;
				shared_structure.section_alignment_isvalid_ = EleCorrectness::not_valid;
				data_container.structures_attributes.optional_header_normal_ = false;
				result.information_list_.push_back(
					relationship_issue(
						Core::Severity::WARNING_MED,
						"SectionAlignment",
						"Optional Header",
						"FileAlignment",
						"Optional Header",
						"less than",
						static_cast<uint64_t>(shared_structure.peheader_offset_) + 24 + 32
					)
				);
			}
			// 可疑：对齐粒度过于整齐
			else if (shared_structure.section_alignment_ == shared_structure.file_alignment_) {
				data_container.structures_attributes.optional_header_normal_ = false;
				result.information_list_.push_back(
					detailed_information(
						Core::Severity::SUSPICIOUS,
						"SectionAlignment & FileAlignment",
						"Optional Header",
						"Equal values",
						static_cast<uint64_t>(shared_structure.peheader_offset_) + 24 + 32
					)
				);
			}
		}
		else {
			data_container.structures_attributes.optional_header_normal_ = false;
			shared_structure.file_alignment_isvalid_ = EleCorrectness::uncertain;
			shared_structure.section_alignment_isvalid_ = EleCorrectness::uncertain;
		}

		/* address_of_entrypoint值检验 */
		// 异常：addressofentrypoint值为0
		if (shared_structure.address_of_entrypoint_ == 0) {
			shared_structure.address_of_entrypoint_isvalid_ = EleCorrectness::not_valid;
			data_container.structures_attributes.optional_header_normal_ = false;
			result.information_list_.push_back(
				invalid_value(
					Core::Severity::WARNING_MED,
					"AddressOfEntryPoint",
					"Optional Header",
					shared_structure.address_of_entrypoint_,
					static_cast<uint64_t>(shared_structure.peheader_offset_) + 24 + 16,
					false
				)
			);
		}
		/*节对齐验证需要结合file和sectionalignment计算
		节区验证需要知道节区具体位置，地址计算需要结合imagebase，此处暂时不验证*/

		/* size_of_image值检验 */
		if (shared_structure.section_alignment_isvalid_ == EleCorrectness::not_valid) {
			data_container.structures_attributes.optional_header_normal_ = false;
			shared_structure.size_of_image_isvalid_ = EleCorrectness::uncertain;
		}
		// 异常：sizeofimage值非sectionalignment倍数 /* ！！！！需要修复除零错误！！！！ */
		else if (shared_structure.section_alignment_ != 0 
			&& shared_structure.size_of_image_ % shared_structure.section_alignment_ != 0 ) {
			shared_structure.size_of_image_isvalid_ = EleCorrectness::not_valid;
			data_container.structures_attributes.optional_header_normal_ = false;
			result.information_list_.push_back(
				invalid_value(
					Core::Severity::WARNING_MED,
					"SizeOfImage",
					"Optional Header",
					shared_structure.size_of_image_,
					static_cast<uint64_t>(shared_structure.peheader_offset_) + 24 + 56,
					false
				)
			);
		}

		/* address_of_entrypoint、size_of_image联合检验 */
		// 异常：addressofentrypoint所示地址超过内存大小
		if (shared_structure.address_of_entrypoint_ >= shared_structure.size_of_image_ && shared_structure.size_of_image_isvalid_ == EleCorrectness::valid) {
			shared_structure.address_of_entrypoint_isvalid_ = EleCorrectness::not_valid;
			data_container.structures_attributes.optional_header_normal_ = false;
			result.information_list_.push_back(
				address_out_of_range(
					Core::Severity::WARNING_MED,
					"AddressOfEntryPoint",
					"Optional Header",
					shared_structure.address_of_entrypoint_
				)
			);
		}
		/* 暂定区域：addressofentrypoint指向的节区验证 */
		/* addressofentrypoint指向的节区属性合法性验证 */
		/* AddressOfEntryPoint + ImageBase验证入口点的绝对内存地址是否有效。等，*/
		/* 暂定区域：以上字段分析以及，长度计算，以及，延迟导入分析 */

		/* dataderectory[5]值检验 */
		// 普通信息：无显式重定位表
		if (shared_structure.relocation_table_RVA_ == 0) {
			data_container.structures_attributes.optional_header_normal_ = false;
			result.information_list_.push_back(
				detailed_information(
					Core::Severity::INFO_LOW,
					"Data Directory[5]",
					"Optional Header",
					"No Relocation Table.",
					static_cast<uint64_t>(shared_structure.peheader_offset_) + 24 + 136
				)
			);
		}
		// 异常：dataderectory[5]->size与RVA值不匹配
		else {
			if (shared_structure.relocation_table_size_ == 0) {
				data_container.structures_attributes.optional_header_normal_ = false;
				result.information_list_.push_back(
					invalid_value(
						Core::Severity::WARNING_MED,
						"Data Directory[5] Size",
						"Optional Header",
						shared_structure.relocation_table_size_,
						static_cast<uint64_t>(shared_structure.peheader_offset_) + 24 + 136,
						false
					)
				);
			}
			// 异常：dataderectory[5]->virtualaddress所示地址超过内存大小
			if (shared_structure.relocation_table_RVA_ < 0x1000 ||
				shared_structure.relocation_table_RVA_ > 0x7FFFFFFF) {
				data_container.structures_attributes.optional_header_normal_ = false;
				result.information_list_.push_back(
					address_out_of_range(
						Core::Severity::WARNING_MED,
						"Data Directory[5] VirtualAddress",
						"Optional Header",
						shared_structure.relocation_table_RVA_
					)
				);
			}
		}
		// 可疑：dataderectory[5]->virtualaddress未按四字节对齐
		if ((shared_structure.relocation_table_RVA_ & 0x3) != 0) {
			data_container.structures_attributes.optional_header_normal_ = false;
			result.information_list_.push_back(
				detailed_information(
					Core::Severity::SUSPICIOUS,
					"Data Directory[5] VirtualAddress",
					"Optional Header",
					"Not aligned to 4 bytes.",
					static_cast<uint64_t>(shared_structure.peheader_offset_) + 24 + 136
				)
			);
		}

		/* dataderectory[9]值检验 */
		// 普通信息：无显示TLS表
		if (shared_structure.tls_table_RVA_ == 0) {
			result.information_list_.push_back(
				detailed_information(
					Core::Severity::INFO_LOW,
					"Data Directory[9]",
					"Optional Header",
					"No TLS Table.",
					static_cast<uint64_t>(shared_structure.peheader_offset_) + 24 + 168
				)
			);
		}
		// 异常：dataderectory[9]->size与RVA值不一致
		else {
			if (shared_structure.tls_table_size_ == 0) {
				data_container.structures_attributes.optional_header_normal_ = false;
				result.information_list_.push_back(
					invalid_value(
						Core::Severity::WARNING_MED,
						"Data Directory[9] Size",
						"Optional Header",
						shared_structure.tls_table_size_,
						static_cast<uint64_t>(shared_structure.peheader_offset_) + 24 + 168,
						false
					)
				);
			}
			// 异常：dataderectory[9]->virtualaddress所示地址超过内存大小
			if (shared_structure.tls_table_RVA_ < 0x1000 || 
			shared_structure.tls_table_RVA_ > 0x7FFFFFFF) {
				data_container.structures_attributes.optional_header_normal_ = false;
				result.information_list_.push_back(
					address_out_of_range(
						Core::Severity::WARNING_MED,
						"Data Directory[9] VirtualAddress",
						"Optional Header",
						shared_structure.tls_table_RVA_
					)
				);
			}
		}
		// 可疑：dataderectory[9]->virtualaddress未按四字节对齐
		if ((shared_structure.tls_table_RVA_ & 0x3) != 0) {
			data_container.structures_attributes.optional_header_normal_ = false;
			result.information_list_.push_back(
				detailed_information(
					Core::Severity::SUSPICIOUS,
					"Data Directory[9] VirtualAddress",
					"Optional Header",
					"Not aligned to 4 bytes.",
					static_cast<uint64_t>(shared_structure.peheader_offset_) + 24 + 168
				)
			);
		}
	}
	data_container.diarelist.push_back(result);
	data_container.out_range_[3] = 1;
	return true;
}

bool PEanalyzer::section_headers_analysis(Structuresults& data_container) {
	Diaresults result;
	int i = 0;

	result.component_name_ = "IMAGE_SECTION_HEADERs";
	result.file_offset_ = shared_structure.peheader_offset_ + 20 + data_container.diarelist[3].data_size_;
	
	data_container.structures_attributes.head_end_address_ = result.file_offset_;
	data_container.structures_attributes.section_start_address_ = result.file_offset_;
	
	size_t read_offset_copy = read_offset; // 复用缓冲区偏移备份
	int section_error_status_code = 0;     // 参考 database.cpp -> is_this_section_valid() 函数的返回值定义
	bool range_sum = true;

	/* 第一层大循环 基于宽松条件首次扫描节区数量（shared_structure.detected_section_count_） */ 
	for (; i < REASONABLE_MAX_SECTIONS; i++) {
		SectionHeader current_section = {};

		if (read_offset >= 0 && read_offset < BUFFER_SIZE) {
			std::memcpy(&current_section,
				mulbuffer + read_offset,
				sizeof(SectionHeader));
		}
		else {
			try {
				// 临时分析缓冲区读取复用缓冲区时偏移异常。
				throw std::out_of_range("Section Header: Temporary analysis buffer offset out of range when reading from shared buffer.");
			}
			catch (const std::out_of_range& e) {
				// 临时分析缓冲区读取复用缓冲区时偏移异常。

				data_container.crash_imformation_set(
					error_category::OFFSET_OUT_OF_RANGE,
					"Section Header: Temporary analysis buffer offset out of range when reading from shared buffer."
				);
				data_container.diarelist.push_back(result);
				return false;
			}
		}

		if (is_this_section_valid(current_section, shared_structure, data_container) == 0) {
			read_offset += sizeof(SectionHeader);
			shared_structure.detected_section_count_ += 1;
			continue;
		}
		else {
			section_error_status_code = is_this_section_valid(current_section, shared_structure, data_container);
		}
		break;
	}

	/* 第一层大循环结束后处理 */
	// 节区因前面字段错误而导致无法扫描，此处直接中止分析节区头部分，仅输出至可选头分析结果
	if (data_container.num_of_scanned_blocks_ < 5) {
		return true;
	}

	// 数量矛盾判断与重置
	bool has_contradiction = true;
	int max_num = shared_structure.detected_section_count_;
	int theoretical_max_sections = (shared_structure.size_of_headers_ - (result.file_offset_)) / 40;
	if (data_container.fileheader.numberofsections == shared_structure.detected_section_count_ &&
	shared_structure.detected_section_count_ <= theoretical_max_sections) {
		has_contradiction = false;
	}
	// 如果是因为扫描到全零节区头而停止扫描的，可认为是扫描正常结束，不进行数量重置
	if (section_error_status_code != 6 && has_contradiction) {
		if (theoretical_max_sections > max_num) { max_num = theoretical_max_sections; }
		if (data_container.fileheader.numberofsections > max_num) { max_num = data_container.fileheader.numberofsections; }
	}
	// 排除恶意构造的第一个节区全0导致扫描器崩溃情况
	if (section_error_status_code == 6 && max_num == 0) {
		max_num = data_container.fileheader.numberofsections != 0 ? data_container.fileheader.numberofsections : theoretical_max_sections;
	}

	/* 第二层大循环 基于严格条件重复扫描进行异常分析 */
	read_offset = read_offset_copy; // 重置复用缓冲区指针
	for (size_t j = 0; j < max_num; j++) {
		if (j == REASONABLE_MAX_SECTIONS) {
			// 检测到可能的节区头数量过多，工具将仅分析至前128个节区头。
			result.additional_information.push_back("Detected excessive number of section headers; analysis limited to first 128 sections.");
			// data_container.max_number_of_possible_sections = j;
			data_container.out_range_[4] = j;
			break;
		}
		SectionHeader current_section = {};

		if (read_offset >= 0 && read_offset < BUFFER_SIZE) {
			std::memcpy(&current_section,
				mulbuffer + read_offset,
				sizeof(SectionHeader));
		}
		else {
			try {
				// 临时分析缓冲区读取复用缓冲区时偏移异常。
				throw std::out_of_range("Section Header: Temporary analysis buffer offset out of range when reading from shared buffer.");
			}
			catch (const std::out_of_range& e) {
				// 临时分析缓冲区读取复用缓冲区时偏移异常。
				data_container.crash_imformation_set(
					error_category::OFFSET_OUT_OF_RANGE,
					"Section Header: Temporary analysis buffer offset out of range when reading from shared buffer."
				);
				data_container.diarelist.push_back(result);
				data_container.out_range_[4] = j - 1 >= 0 ? j - 1 : 0;
				return false;
			}
		}

		/* 伪节区过滤 */
		if (current_section.VirtualSize == 0 && current_section.SizeOfRawData == 0 && current_section.PointerToRawData == 0) {
			read_offset += sizeof(SectionHeader);
			continue;
		}

		data_container.sectionheaders.push_back(current_section);

		SectionImformation section_imformation_element;
		data_container.section_attributes.push_back(section_imformation_element); // 创建记录节区属性的结构体
		section_characteristic_judge(current_section.Characteristics, data_container); // 根据characteristic判断节区展现的实际属性并存入结构体
		section_name_check(current_section.Name, current_section.Characteristics, result, j, data_container); // 检测Name字段，如果为常见值则标记可能属性，并与上述属性判断结果联合判断
		// 如果Name非常见值，则判断characteristic本身属性组合是否有问题
		if (!data_container.section_attributes[j].known_combination_) {
			section_characteristic_check(current_section.Characteristics, result, j, data_container);
		}

		// 内存地址区间记录
		uint32_t t_imagebase;
		switch (shared_structure.bitness_) {
		case 32:
			t_imagebase = shared_structure.imagebase32_;
			break;
		case 64:
			t_imagebase = shared_structure.imagebase64_;
			break;
		default:
			try {
				t_imagebase = shared_structure.imagebase32_ == 0 ? shared_structure.imagebase64_ : shared_structure.imagebase32_;
				if (t_imagebase == 0) {
					// SharedStructure->bitness值出错，无法读取偏移值。
					throw std::runtime_error("SharedStructure->bitness :value error, unable to read offset value.");
				}
			}
			catch (std::runtime_error& e) {
				/* 暂定处理，需要修改，不应该是outputrange，建议新增变量记录合理节区输出数量 */
				data_container.num_of_scanned_blocks_ = 4;
				data_container.out_range_[4] = j - 1 >= 0 ? j - 1 : 0;
				return true;
			}
			break;
		}

		uint32_t aligned_virtual_size = ((current_section.VirtualSize + shared_structure.section_alignment_ - 1) /
			shared_structure.section_alignment_) * shared_structure.section_alignment_;
		SectionRange m_section_range(
			j,
			(t_imagebase + current_section.VirtualAddress),
			t_imagebase + current_section.VirtualAddress + aligned_virtual_size,
			current_section.VirtualSize,
			aligned_virtual_size
		);
		data_container.memory_interval_table.push_back(m_section_range);

		SectionRange s_section_range(
			j, 
			current_section.PointerToRawData,
			current_section.PointerToRawData + current_section.SizeOfRawData,
			(current_section.VirtualSize < current_section.SizeOfRawData) ? current_section.VirtualSize : current_section.SizeOfRawData,
			current_section.SizeOfRawData
		);
		data_container.storage_interval_table.push_back(s_section_range);

		data_container.structures_attributes.section_end_address_ = 
			s_section_range.end >= data_container.structures_attributes.section_end_address_ ? s_section_range.end : data_container.structures_attributes.section_end_address_;

		std::string msg1, msg2;

		// 内存区间乱序、重叠、空洞检查
		for (size_t j1 = 0; j1 < j; j1++) {
			// 内存分布重叠+乱序扫描
			int judgment_code = interval_relation_judgment(data_container.memory_interval_table[j1].begin, data_container.memory_interval_table[j1].end,
				data_container.memory_interval_table[j].begin, data_container.memory_interval_table[j].end);
			try {
				if (judgment_code == 0) {
					/*msg1 = "扫描至sectionheader[" + std::to_string(j) + "]处理内存区间情况时出现不合理计算范围或出现未知区间状态。";*/
					msg1 = "Scanning sectionheader[" + std::to_string(j) + "] for memory interval relation detected unreasonable calculation range or unknown interval status.";
					throw std::runtime_error(msg1);
				}
			}
			catch (std::runtime_error) {
				/* 暂定处理 
				data_container.num_of_scanned_blocks_ = 4;*/
				range_sum = false;
				break;
			}
			if (judgment_code == -1) {
				// 警告：区间[j]地址计算出现负数，存在不合理计算范围
				result.information_list_.push_back(
					indexed_issue(
						Core::Severity::SUSPICIOUS,
						"Section Header",
						j,
						"The address calculation of interval [" + std::to_string(j) + "]  resulted in a negative number, indicating an unreasonable calculation range in the memory.",
						s_section_range.begin
					)
				);
			}
			if (judgment_code == 2 || judgment_code == 5) { // 有重叠现象
				// 可疑：区间[j]所示的映射区间与[j1]所示节区重叠
				msg1 = "There is overlap with the section area shown in [" + std::to_string(j1) + "] in the memory.";
				result.information_list_.push_back(
					indexed_issue(
						Core::Severity::SUSPICIOUS,
						"Section Header",
						j,
						msg1,
						s_section_range.begin
					)
				);
			}
			if (judgment_code == 4 || judgment_code == 6) { // 有乱序现象，乱序定义指节区和节区头顺序不一致
				// 可疑：区间[j]所示的映射区间与[j1]所示节区乱序
				msg1 = "The section area shown in [" + std::to_string(j1) + "] is out of order in the memory.";
				result.information_list_.push_back(
					indexed_issue(
						Core::Severity::SUSPICIOUS,
						"Section Header",
						j,
						msg1,
						s_section_range.begin
					)
				);
				data_container.m_orderliness = false;
			}
		}
		if (data_container.num_of_scanned_blocks_ < 5) {
			break;
		}
		// 内存区间排序
		if (max_num == j + 1 && !data_container.m_orderliness) {
			interval_insertion_sort(data_container.memory_interval_table);
		}
		if (max_num == j + 1 && !interval_hole_scan(data_container.memory_interval_table)) {
			// 可疑：sectionheader所示节区在内存映射中存在空洞现象
			result.information_list_.push_back(
				regular_issue(
					Core::Severity::SUSPICIOUS,
					"Section Header",
					"Section areas may have holes in the memory map.",
					s_section_range.begin
				)
			);
		}
		// 外存区间乱序、重叠、空洞检查
		for (size_t j2 = 0; j2 < j; j2++) {
			// 外存分布重叠+乱序扫描
			int judgment_code = interval_relation_judgment(data_container.storage_interval_table[j2].begin, data_container.storage_interval_table[j2].end,
				data_container.storage_interval_table[j].begin, data_container.storage_interval_table[j].end);
			try {
				if (judgment_code == 0) {
					/* 扫描至sectionheader[j]处理内存区间情况时出现不合理计算范围或出现未知区间状态。 */
					msg1 = "When scanning to sectionheader[" + std::to_string(j) + "] when processing the memory interval, an unreasonable calculation range or an unknown interval status appears.";
					throw std::runtime_error(msg1);
				}
			}
			catch (std::runtime_error) {
				/* 暂定处理 
				data_container.num_of_scanned_blocks_ = 4;*/
				range_sum = false;
				break;
			}
			if (judgment_code == -1) {
				// 警告：区间[j]地址计算出现负数，存在不合理计算范围
				result.information_list_.push_back(
					indexed_issue(
						Core::Severity::SUSPICIOUS,
						"Section Header",
						j,
						"The address calculation of interval [" + std::to_string(j) + "]  resulted in a negative number, indicating an unreasonable calculation range in the external memory.",
						s_section_range.begin
					)
				);
			}
			if (judgment_code == 2 || judgment_code == 5) { // 有重叠现象
				// 可疑：区间[j]所示的外存区间与[j2]所示节区重叠
				result.information_list_.push_back(
					indexed_issue(
						Core::Severity::SUSPICIOUS,
						"Section Header",
						j,
						"There is overlap with the section area shown in [" + std::to_string(j2) + "] in the external memory.",
						s_section_range.begin
					)
				);
			}
			if (judgment_code == 4 || judgment_code == 6) { // 有乱序现象
				// 可疑：区间[j]所示的外存区间与[j2]所示节区乱序
				result.information_list_.push_back(
					indexed_issue(
						Core::Severity::SUSPICIOUS,
						"Section Header",
						j,
						"The section area shown in [" + std::to_string(j2) + "] is out of order in the external memory.",
						s_section_range.begin
					)
				);
				data_container.s_orderliness = false;
			}
		}
		if (data_container.num_of_scanned_blocks_ < 5) {
			break;
		}
		if (max_num == j + 1 && !data_container.s_orderliness) {
			interval_insertion_sort(data_container.storage_interval_table);
		}
		if (max_num == j + 1 && !interval_hole_scan(data_container.storage_interval_table)) {
			// 可疑：sectionheader所示节区在文件中存在空洞现象
			result.information_list_.push_back(
				regular_issue(
					Core::Severity::SUSPICIOUS,
					"Section Header",
					"Section areas may have holes in the file.",
					s_section_range.begin
				)
			);
		}

		// 诊断异常区域（终止条件）
		// 地址问题和字段的混合问题
		// 在非 .bss、.rdata 节出现 VirtualSize 大于 SizeOfRawData 现象
		if (current_section.VirtualSize > current_section.SizeOfRawData &&
			!(data_container.section_attributes[j].known_combination_ &&
				(section_name_match(current_section.Name) == 6683 || section_name_match(current_section.Name) == 8268
					)
				)
			) 
		{
			// 且两者差值大于 4KB，标记为可疑
			if (current_section.VirtualSize - current_section.SizeOfRawData > 4096) {
				result.information_list_.push_back(
					relationship_issue(
						Core::Severity::SUSPICIOUS,
						"VirtualSize",
						"IMAGE_SECTION_HEADER",
						"SizeOfRawData",
						"IMAGE_SECTION_HEADER",
						"VirtualSize is greater than SizeOfRawData.",
						read_offset
					)
				);
			}
			// 超出内存页对齐范围，存在内存未初始化区域
			if (m_section_range.size > s_section_range.size) {
				result.information_list_.push_back(
					detailed_information(
						Core::Severity::SUSPICIOUS,
						"VirtualSize & SizeOfRawData",
						"IMAGE_SECTION_HEADER[" + std::to_string(j) + "]",
						"Uninitialized memory appears in sections other than .bss and .rdata",
						read_offset
					)
				);
			}
		}
		// VirtualSize 为0但 VirtualAddress 与其他节重叠
		
		// VirtualSize 与 SizeOfRawData 均为0且节区属性包含可执行/可写
		// 节区重叠（VirtualAddress 计算后范围重叠）
		//  VirtualAddress=0 且非第一个节区
		//SizeOfRawData=0 但 VirtualSize>0 且节区属性异常
		// SizeOfRawData 与 VirtualSize 均为0
		// 节区数据重叠（PointerToRawData + SizeOfRawData 重叠）
		// 节区间文件数据重叠
		// PointerToRawData = 0（非特殊情况）
		// 指向文件末尾之后（但SizeOfRawData=0）

		read_offset += sizeof(SectionHeader);
		if (range_sum) {
			data_container.out_range_[4] += 1;
		}
	}

	data_container.diarelist.push_back(result);
	return true;
}

// 导入表，data_container.out_range_[5]、data_container.diarelist[5]
bool PEanalyzer::import_descriptor_seeker(Structuresults& data_container) {
	clear_buffer();
	Diaresults result;

	result.component_name_ = "IMAGE_IMPORT_DESCRIPTOR";

	/* 前置工作，dataderectory[1]值检验 */
	// 可疑：导入表缺失
	if (shared_structure.import_table_RVA_ == 0) {
		result.information_list_.push_back(
			detailed_information(
				Core::Severity::SUSPICIOUS,
				"Data Directory[1]",
				"Optional Header",
				"No Import Table.",
				static_cast<uint64_t>(shared_structure.peheader_offset_) + 24 + 104
			)
		);
		data_container.structures_attributes.import_descriptor_found_ = false;
	}
	// 警告：dataderectory[1]size值为0，但存在导入表
	else {
		if (shared_structure.import_table_size_ == 0) {
			result.information_list_.push_back(
				invalid_value(
					Core::Severity::WARNING_MED,
					"Data Directory[1] Size",
					"Optional Header",
					shared_structure.import_table_size_,
					static_cast<uint64_t>(shared_structure.peheader_offset_) + 24 + 104,
					false
				)
			);
			data_container.structures_attributes.optional_header_normal_ = false;
		}

		// 警告：dataderectory[1]->virtualaddress所示地址超出内存大小
		if (shared_structure.import_table_RVA_ < 0x1000 ||
			shared_structure.import_table_RVA_ > 0x7FFFFFFF) {
			result.information_list_.push_back(
				address_out_of_range(
					Core::Severity::WARNING_MED,
					"Data Directory[1] VirtualAddress",
					"Optional Header",
					shared_structure.import_table_RVA_
				)
			);
			data_container.structures_attributes.optional_header_normal_ = false;
			data_container.structures_attributes.import_descriptor_found_ = false;
		}

		// 可疑：dataderectory[1]->virtualaddress未按四字节对齐
		if ((shared_structure.import_table_RVA_ & 0x3) != 0) {
			result.information_list_.push_back(
				detailed_information(
					Core::Severity::SUSPICIOUS,
					"Data Directory[1] VirtualAddress",
					"Optional Header",
					"Not aligned to 4 bytes.",
					static_cast<uint64_t>(shared_structure.peheader_offset_) + 24 + 104
				)
			);
			data_container.structures_attributes.optional_header_normal_ = false;
		}
	}

	size_t qst_count = 0; // 有记录的条目数量
	// 计算IMAGE_IMPORT_DESCRIPTOR起始地址在哪个节表
	if (data_container.structures_attributes.import_descriptor_found_) {
		unsigned int index = 0;
		bool found = false;
		for (size_t i = 0; i < data_container.storage_interval_table.size(); i++) {
			uint32_t section_start = data_container.sectionheaders[i].VirtualAddress;
			uint32_t section_end = section_start + data_container.sectionheaders[i].VirtualSize;

			if (shared_structure.import_table_RVA_ >= section_start &&
				shared_structure.import_table_RVA_ < section_end) {
				index = i;
				found = true;
				break;
			}
		}
		if (!found) {
			data_container.structures_attributes.import_descriptor_found_ = false;
			data_container.diarelist.push_back(result);
			return true;
		}

		// 填充数据
		unsigned int descriptor_address =
			shared_structure.import_table_RVA_ -
			data_container.sectionheaders[index].VirtualAddress +
			data_container.sectionheaders[index].PointerToRawData;
		unsigned int read_bytes = file_size_ - descriptor_address >= BUFFER_SIZE ? BUFFER_SIZE : file_size_ - descriptor_address;
		if (descriptor_address < file_size_) {
			pedata_.seekg(descriptor_address);
			if (!pedata_) {
				data_container.crash_imformation_set(
					// 文件流异常，文件指针移动失败，可能文件未正确打开或已损坏。
					error_category::FILE_SEEK_FAILED,
					"IMAGE_IMPORT_DESCRIPTOR: File stream exception, failed to move file pointer, \nthe file may not have been opened correctly or is corrupted."
				);
				data_container.diarelist.push_back(result);
				data_container.out_range_[5] = 0;
				return false;
			}
			pedata_.read(reinterpret_cast<char*>(mulbuffer), read_bytes);
			if (pedata_.gcount() != read_bytes) {
				data_container.crash_imformation_set(
					// 文件流读取数据到内存缓冲区失败。
					error_category::FILE_READ_FAILED,
					"IMAGE_IMPORT_DESCRIPTOR: Failed to read data from the file stream into the memory buffer."
				);
				data_container.diarelist.push_back(result);
				data_container.out_range_[5] = 0;
				return false;
			}
		}

		data_container.structures_attributes.import_descriptor_start_address_ = descriptor_address;

		size_t des_offset = 0;
		size_t count = 0;     // 扫描的导入表项数
		while (des_offset + sizeof(ImportDescriptor) <= read_bytes && 
		data_container.import_descriptor.size() < REASONABLE_MAX_IMPORT_DESCRIPTORS){
			ImportDescriptor current_descriptor;
			std::memcpy(&current_descriptor,
				mulbuffer + des_offset,
				sizeof(ImportDescriptor));

			// 结束标志
			if (current_descriptor.FirstThunk == 0 &&
				current_descriptor.ForwarderChain == 0 &&
				current_descriptor.Name == 0 &&
				current_descriptor.OriginalFirstThunk == 0 &&
				current_descriptor.TimeDateStamp == 0) {
				break;
			}

			// 警告：Name不能为 0（每个 DLL 必须有名字）
			if (current_descriptor.Name == 0) {
				qst_count++;
				result.information_list_.push_back(
					indexed_issue(
						Core::Severity::WARNING_MED,
						"IMAGE_IMPORT_DESCRIPTOR",
						count,
						"The pointer to the DLL name string is null.",
						descriptor_address + des_offset + 12
					)
				);
			}
			// Name必须落在某个节的范围内
			if (current_descriptor.Name < data_container.structures_attributes.section_start_address_ ||
			current_descriptor.Name >= data_container.structures_attributes.section_end_address_) {
				qst_count++;
				result.information_list_.push_back(
					indexed_issue(
						Core::Severity::WARNING_MED,
						"IMAGE_IMPORT_DESCRIPTOR",
						count,
						"DLL name address exceeds section address range.",
						descriptor_address + des_offset + 12
					)
				);
			}
			// FirstThunk和OriginalFirstThunk至少一个非零
			if (current_descriptor.FirstThunk == 0 || current_descriptor.OriginalFirstThunk == 0) {
				if (current_descriptor.FirstThunk == 0 && current_descriptor.OriginalFirstThunk == 0) {
					qst_count++;
					result.information_list_.push_back(
						indexed_issue(
							Core::Severity::WARNING_MED,
							"IMAGE_IMPORT_DESCRIPTOR",
							count,
							"Both FirstThunk and OriginalFirstThunk are missing.",
							descriptor_address + des_offset
						)
					);
				}
			}
			else {
				// 如果两个都非零，通常指向不同位置
				if (current_descriptor.FirstThunk == current_descriptor.OriginalFirstThunk) {
					qst_count++;
					result.information_list_.push_back(
						indexed_issue(
							Core::Severity::SUSPICIOUS,
							"IMAGE_IMPORT_DESCRIPTOR",
							count,
							"FirstThunk and OriginalFirstThunk point to the same area.",
							descriptor_address + des_offset
						)
					);
				}
			}
			// FirstThunk必须落在某个节的范围内
			if (current_descriptor.FirstThunk < data_container.structures_attributes.section_start_address_ ||
			current_descriptor.FirstThunk >= data_container.structures_attributes.section_end_address_) {
				qst_count++;
				result.information_list_.push_back(
					indexed_issue(
						Core::Severity::WARNING_MED,
						"IMAGE_IMPORT_DESCRIPTOR",
						count,
						"FirstThunk is not within the section area.",
						descriptor_address + des_offset
					)
				);
			}
			// OriginalFirstThunk必须落在某个节的范围内
			if (current_descriptor.OriginalFirstThunk < data_container.structures_attributes.section_start_address_ ||
			current_descriptor.OriginalFirstThunk >= data_container.structures_attributes.section_end_address_) {
				qst_count++;
				result.information_list_.push_back(
					indexed_issue(
						Core::Severity::WARNING_MED,
						"IMAGE_IMPORT_DESCRIPTOR",
						count,
						"OriginalFirstThunk is not within the section area.",
						descriptor_address + des_offset + 16
					)
				);
			}
			// 通常应该指向可读节（.rdata, .idata）
			
			// Thunk 数组通常是 4 字节对齐
			if(current_descriptor.FirstThunk % 4 != 0 || current_descriptor.OriginalFirstThunk % 4 != 0) {
				qst_count++;
				result.information_list_.push_back(
					indexed_issue(
						Core::Severity::SUSPICIOUS,
						"IMAGE_IMPORT_DESCRIPTOR",
						count,
						"FirstThunk or OriginalFirstThunk is not aligned to 4 bytes.",
						descriptor_address + des_offset
					)
				);
			}

			data_container.import_descriptor.push_back(current_descriptor);
			des_offset += sizeof(ImportDescriptor);
			data_container.out_range_[5] += 1;
			count++;
		}

		data_container.structures_attributes.import_descriptor_end_address_ = descriptor_address + 20 * count;
	}

	if (qst_count >= 10) {
		result.additional_information.push_back("Too much imported table information has been scanned and has been collapsed");
	}
	data_container.diarelist.push_back(result);
	return true;
}