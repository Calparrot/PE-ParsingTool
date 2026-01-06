#include <fstream>
#include <cstdint>
#include <sstream>
#include <cstring>
#include <algorithm>

#include "peanalyzer.h"
#include "database.h"

constexpr int REASONABLE_MAX_SECTIONS = 128;

SharedStructure shared_structure{};
extern structuresults data_container;

/*
	interval_relation_judgment ：两个区间关系判断函数
	interval_insertion_sort    ：处理区间的插入排序函数
	interval_hole_scan         ：区间缺口扫描函数（要求传入参数已排序）
*/

/* 普通工具函数 */
static int interval_relation_judgment(uint64_t f_begin, uint64_t f_end, uint64_t a_begin, uint64_t a_end) { // front和after的始末值
	if (f_begin > f_end || a_begin > a_end) {
		return -1;    // 无效区间
	}
	if (f_begin < a_begin && f_begin < a_end) {
		if (f_end < a_end && f_end < a_begin) {
			return 1; // 正常
		}
		else if (f_end < a_end && f_end >= a_begin) {
			return 2; // front后部与after前部重叠
		}
		else if (f_end >= a_end && f_end >= a_begin) {
			return 3; // 完全重叠
		}
	}
	else if (f_begin >= a_begin && f_begin < a_end) {
		return 4;     // front前部与after后部重叠 + 乱序
	}
	else if (f_begin >= a_begin && f_begin >= a_end) {
		return 5;     // 乱序
	}
	return 0;         // 奇怪的情况
}

static void interval_insertion_sort(std::vector<SectionRange>& input_vector) {
	size_t n = input_vector.size();
	for (size_t i = 1; i < n; i++) {
		SectionRange current = input_vector[i];
		size_t j = i - 1;
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

std::string PEanalyzer::field_interpretation(uint16_t inputmachine) {
	switch (inputmachine) {
	case 0x0000: return "【异常】machine值为0，无效架构";
	case 0x014C: return "【普通】machine对应架构：Intel 386 (32位x86)";
	case 0x8664:
		shared_structure.bitness_ = 64;
		return "【普通】machine对应架构：AMD64 (64位x86)";
	case 0x01C0: return "【普通】machine对应架构：ARM LE";
	case 0x01C4: return "【普通】machine对应架构：ARMv7 THUMB LE";
	case 0xAA64:
		shared_structure.bitness_ = 64;
		return "【普通】machine对应架构：ARM64 LE";
	case 0x0200:
		shared_structure.bitness_ = 64;
		return "【普通】machine对应架构：Intel Itanium";
	case 0x0162: return "【普通】machine对应架构：MIPS R3000";
	case 0x0166: return "【普通】machine对应架构：MIPS R4000";
	case 0x0168: return "【普通】machine对应架构：MIPS R10000";
	case 0x0169: return "【普通】machine对应架构：MIPS WCE v2";
	case 0x0184:
		shared_structure.bitness_ = 64;
		return "【普通】machine对应架构：Alpha AXP";
	case 0x01A2: return "【普通】machine对应架构：SH3";
	case 0x01A3: return "【普通】machine对应架构：SH3 DSP";
	case 0x01A6: return "【普通】machine对应架构：SH4";
	case 0x01A8:
		shared_structure.bitness_ = 64;
		return "【普通】machine对应架构：SH5";
	case 0x01C2: return "【普通】machine对应架构：ARM Thumb-2 LE";
	case 0x01D3: return "【普通】machine对应架构：Matsushita AM33";
	case 0x01F0: return "【普通】machine对应架构：PowerPC";
	case 0x01F1: return "【普通】machine对应架构：PowerPC FP";
	case 0x0266: return "【普通】machine对应架构：MIPS16";
	case 0x0366: return "【普通】machine对应架构：MIPS with FPU";
	case 0x0466: return "【普通】machine对应架构：MIPS16 with FPU";
	case 0x0520: return "【普通】machine对应架构：Tricore";
	case 0x0EBC:
		shared_structure.bitness_ = 82;
		return "【普通】machine对应架构：EFI Byte Code";
	case 0x9041: return "【普通】machine对应架构：M32R";
	case 0xC0EE: return "【普通】machine对应架构：CEE";
	default: return "【非标准】machine（目标CPU架构）无匹配值，未知架构";
	}
}

void PEanalyzer::magic_check(uint16_t inputmagic, Diaresults& inputresult, int& length) {
	switch (inputmagic) {
	case 0x20B:
		shared_structure.bitness_ = 64;
		length = 238;
		inputresult.informations_.push_back("【普通】位宽：64位");
		break;
	case 0x10B:
		shared_structure.bitness_ = 32;
		length = 222;
		inputresult.informations_.push_back("【普通】位宽：32位");
		break;
	case 0x107:
		shared_structure.bitness_ = 82;
		length = 110;
		inputresult.informations_.push_back("【普通】位宽：ROM映像");
		break;
	default:
		inputresult.informations_.push_back("【异常】magic（魔术字）无匹配值，未知架构。");
		inputresult.warnings_.push_back("magic 字段无效或未知架构。");
		inputresult.field_anomalies_.push_back("magic 字段匹配失败。");
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

void PEanalyzer::section_characteristic_judge(uint32_t input_characteristic) {
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

void PEanalyzer::section_characteristic_check(uint32_t input_characteristic, Diaresults& inputresult, size_t num) {
	std::string msg1 = "sectionheader[" + std::to_string(num) + "]权限异常。";
	std::string msg2 = "sectionheader[" + std::to_string(num) + "]属性逻辑错误。";
	// mem_execute_ + mem_write_
	if (data_container.section_attributes[num].mem_execute_ && data_container.section_attributes[num].mem_write_) {
		std::string msg3 = "【异常】sectionheader[" + std::to_string(num) + "]属性可读+可写，存在安全风险。";
		inputresult.warnings_.push_back(msg1);
		inputresult.informations_.push_back(msg3);
	}
	// mem_shared_ + cnt_uninitialized_data_
	if (data_container.section_attributes[num].mem_shared_ && data_container.section_attributes[num].cnt_uninitialized_data_) {
		std::string msg3 = "【可疑】sectionheader[" + std::to_string(num) + "]属性共享零数据，注意特殊处理。";
		inputresult.informations_.push_back(msg3);
	}
	// mem_write_ + !mem_read_
	if (data_container.section_attributes[num].mem_write_ && !data_container.section_attributes[num].mem_read_) {
		std::string msg3 = "【异常】sectionheader[" + std::to_string(num) + "]属性可执行+不可读，无法正常执行。";
		inputresult.warnings_.push_back(msg1);
		inputresult.informations_.push_back(msg3);
	}
	// mem_execute_ + !mem_read_
	if (data_container.section_attributes[num].mem_execute_ && !data_container.section_attributes[num].mem_read_) {
		std::string msg3 = "【可疑】sectionheader[" + std::to_string(num) + "]属性只写内存，较为少见。";
		inputresult.informations_.push_back(msg3);
	}
	// !mem_read_ + !mem_write_ + !mem_execute_
	if (!data_container.section_attributes[num].mem_execute_ && !data_container.section_attributes[num].mem_read_ && !data_container.section_attributes[num].mem_write_) {
		std::string msg3 = "【异常】sectionheader[" + std::to_string(num) + "]属性不可执行+不可读+不可写，无法正常访问。";
		inputresult.warnings_.push_back(msg1);
		inputresult.informations_.push_back(msg3);
	}
	// 6. cnt_code_ + cnt_uninitialized_data_
	if (data_container.section_attributes[num].cnt_code_ && data_container.section_attributes[num].cnt_uninitialized_data_) {
		std::string msg3 = "【异常】sectionheader[" + std::to_string(num) + "]属性逻辑错误。";
		inputresult.warnings_.push_back(msg2);
		inputresult.informations_.push_back(msg3);
	}
	// 7. cnt_initialized_data_ + cnt_uninitialized_data_
	if (data_container.section_attributes[num].cnt_initialized_data_ && data_container.section_attributes[num].cnt_uninitialized_data_) {
		std::string msg3 = "【异常】sectionheader[" + std::to_string(num) + "]属性逻辑矛盾。";
		inputresult.warnings_.push_back(msg2);
		inputresult.informations_.push_back("【异常】节区属性逻辑错误");
	}
}

int PEanalyzer::section_name_match(const uint8_t input_name[8]) {
	struct NameCompare {
		const uint8_t name[8];
		int id;
	};

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

void PEanalyzer::section_name_check(const uint8_t input_name[8], const uint32_t input_characteristic, Diaresults& inputresult, size_t num) {
	bool judgement_set[7] = {0};
	bool actual_val[7] = {};
	bool is_attribute_common = true;
	int name_id = section_name_match(input_name);
	/*
	[0] bool mem_execute_;               // 内存可执行
    [1] bool mem_read_;                  // 内存可读
    [2] bool mem_write_;                 // 内存可写
    [3] bool mem_shared_;                // 内存共享
    [4] bool cnt_code_;                  // 包含可执行代码 
    [5] bool cnt_initialized_data_;      // 包含已初始化数据
    [6] bool cnt_uninitialized_data_;    // 零初始化
	*/

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
		std::string msg = "【可疑】sectionheader[" + std::to_string(num) + "]->name 字段非常见编译器编译结果。";
		inputresult.informations_.push_back(msg);
		return;
	}

	actual_val[0] = data_container.section_attributes[num].mem_execute_;
	actual_val[1] = data_container.section_attributes[num].mem_read_;
	actual_val[2] = data_container.section_attributes[num].mem_write_;
	actual_val[3] = data_container.section_attributes[num].mem_shared_;
	actual_val[4] = data_container.section_attributes[num].cnt_code_;
	actual_val[5] = data_container.section_attributes[num].cnt_initialized_data_;
	actual_val[6] = data_container.section_attributes[num].cnt_uninitialized_data_;

	if (!memcmp(judgement_set, actual_val, 7)) {
		std::string msg1 = "sectionheader[" + std::to_string(num) + "]权限异常";
		std::string msg2 = "【可疑】sectionheader[" + std::to_string(num) + "]的name值与其期望的权限不匹配。";
		inputresult.warnings_.push_back(msg1);
		inputresult.informations_.push_back(msg2);
	}
	if (!is_attribute_common) {
		std::string msg1 = "sectionheader[" + std::to_string(num) + "]->characteristic值非常见结果。";
		std::string msg2 = "【可疑】sectionheader[" + std::to_string(num) + "]->characteristic值非常见结果。";
		inputresult.warnings_.push_back(msg1);
		inputresult.informations_.push_back(msg2);
	}
	else {
		data_container.section_attributes[num].known_combination_ = true;
	}
}

/* public函数 */
bool PEanalyzer::dosheader_analysis() {
	clear_buffer();
	Diaresults result;
	pedata_.seekg(0, std::ios::beg);
	if (!pedata_) {
		data_container.crash_imformation_set(
			error_category::FILE_SEEK_FAILED,
			"DOS Header（DOS头）：文件流异常，文件指针移动失败，可能文件未正确打开或已损坏。"
		);
		data_container.diarelist.push_back(result);
		return false;
	}
	pedata_.read(reinterpret_cast<char*>(mulbuffer), 64);
	if (pedata_.gcount() != 64) {
		data_container.crash_imformation_set(
			error_category::FILE_READ_FAILED,
			"DOS Header（DOS头）：文件流读取数据到内存缓冲区失败。"
		);
		data_container.diarelist.push_back(result);
		return false;
	}

	result.component_name_ = "DOS Header";
	result.component_type_ = "header";
	result.file_offset_ = 0;
	result.data_size_ = 64;

	std::memcpy(&data_container.dosheader, mulbuffer, sizeof(IMAGE_DOS_HEADER));
	shared_structure.peheader_offset_ = (mulbuffer[60] << 24) | (mulbuffer[61] << 16) | (mulbuffer[62] << 8) | mulbuffer[63];

	if (mulbuffer[0] != 'M' && mulbuffer[1] != 'Z') {
		data_container.dosheader.e_magic = (mulbuffer[0] << 8) | mulbuffer[1];
		data_container.structures_attributes.dos_header_normal_ = false;
		result.field_anomalies_.push_back("不合法的MZ签名，不是有效的PE文件。");
		result.warnings_.push_back("MZ 签名字段异常。");
		result.informations_.push_back("【异常】MZ签名异常，期望值：0x4D5A。");
	}
	
	data_container.diarelist.push_back(result);
	return true;
}

bool PEanalyzer::dosstub_analysis() {
	clear_buffer();
	Diaresults result;
	uint8_t reading_mode = 0; /* 读取方式 0-正常读取，1-分段读取，2-不读取 */
	uint8_t imformation_processing_mode = 1; /* 信息处理方式 1-需要异常 0-不需要异常 */

	pedata_.seekg(64, std::ios::beg);
	if (!pedata_) {
		data_container.crash_imformation_set(
			error_category::FILE_SEEK_FAILED,
			"DOS Stub（DOS存根）：文件流异常，文件指针移动失败，可能文件未正确打开或已损坏。"
		);
		data_container.diarelist.push_back(result);
		return false;
	}
	int count = shared_structure.peheader_offset_ - 64 > 0 ? shared_structure.peheader_offset_ - 64 : 0;

	result.component_name_ = "DOS Stub";
	result.component_type_ = "header";
	result.file_offset_ = 64;
	result.data_size_ = count;

	if (count == 0) {
		data_container.structures_attributes.dos_stub_exist_ = false;
		result.excursion_anomalies_.push_back("DOS存根（DOS Stub）区域缺失。");
	}
	else if (count <= 16) {  // 1-16
		result.excursion_anomalies_.push_back("DOS存根（DOS Stub）过短。");
	}
	else if (count <= 64) {  // 17-64
		result.excursion_anomalies_.push_back("DOS存根（DOS Stub）较短。");
	}
	else if (count <= 128) { // 65-128
		imformation_processing_mode = 0; // 正常
	}
	else if (count <= 256) { // 129-256
		result.excursion_anomalies_.push_back("DOS存根（DOS Stub）较长。");
	}
	else if (count <= 5600) { // 257-5600
		result.excursion_anomalies_.push_back("DOS存根（DOS Stub）过长。");
	}
	else if (count <= 10240) { // 5601-10240
		reading_mode = 1;
		result.excursion_anomalies_.push_back("DOS存根（DOS Stub）过长。");
	}
	else { // >10240
		reading_mode = 2;
		result.excursion_anomalies_.push_back("DOS存根（DOS Stub）过长。");
	}

	// 读取方式处理
	int num_of_bytes_read = 5600;
	int num_of_bytes_remaining = count - 5600;
	switch (reading_mode) {
	case 0:  // 正常读取
		pedata_.read(reinterpret_cast<char*>(mulbuffer), count);
		if (pedata_.gcount() != count) {
			data_container.crash_imformation_set(
				error_category::FILE_READ_FAILED,
				"DOS Stub（DOS存根）：文件流读取数据到内存缓冲区失败。"
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
					error_category::FILE_READ_FAILED,
					"DOS Stub（DOS存根）：文件流读取数据到内存缓冲区失败。"
				);
				data_container.diarelist.push_back(result);
				return false;
			}
			num_of_bytes_read = (num_of_bytes_remaining - num_of_bytes_read > 5600) ? 5600 : (num_of_bytes_remaining - num_of_bytes_read);
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
				error_category::FILE_READ_FAILED,
				"DOS Stub（DOS存根）：文件流异常，文件指针移动失败，可能文件未正确打开或已损坏。"
			);
			data_container.diarelist.push_back(result);
			return false;
		}
		break;
	default: // 异常
		data_container.crash_imformation_set(
			error_category::LOGIC_ERROR,
			"分析 DOS Stub 区域时出现未知参数。"
		);
		throw std::runtime_error("分析 DOS Stub 区域时出现未知参数。");
		break;
	}
	
	// 信息处理
	switch (imformation_processing_mode) {
	case 0:
		data_container.diarelist.push_back(result);
		break;
	case 1:
		data_container.structures_attributes.dos_stub_normal_ = false;
		result.warnings_.push_back("非标准DOS存根（DOS Stub）结构。");
		result.informations_.push_back("【可疑】DOS存根长度非标准，期望长度：约0x40字节");
		result.issuspicious = true;
		data_container.diarelist.push_back(result);
		break;
	default:
		throw std::runtime_error("分析 DOS Stub 区域时出现未知参数。");
		break;
	}

	return true;
}

bool PEanalyzer::file_header_analysis() {
	clear_buffer();
	Diaresults result;

	if (!pedata_.good()) {
		data_container.crash_imformation_set(
			error_category::FILE_SEEK_FAILED,
			"File Header（文件头）：文件流异常，可能文件未正确打开或已损坏。"
		);
		data_container.diarelist.push_back(result);
		return false;
	}
	pedata_.read(reinterpret_cast<char*>(mulbuffer), 5600);
	if (pedata_.gcount() != 5600) {
		data_container.crash_imformation_set(
			error_category::FILE_SEEK_FAILED,
			"File Header（文件头）：文件流读取数据到内存缓冲区失败。"
		);
		data_container.diarelist.push_back(result);
		return false;
	}

	result.component_name_ = "File Header";
	result.component_type_ = "header";
	result.file_offset_ = shared_structure.peheader_offset_;
	result.data_size_ = 20;

	read_offset += 20;

	std::memcpy(&data_container.fileheader, mulbuffer, sizeof(IMAGE_FILE_HEADER));
	shared_structure.machine_ = data_container.fileheader.machine;
	shared_structure.number_of_sections_ = data_container.fileheader.numberofsections;
	shared_structure.size_of_optionalheader_ = data_container.fileheader.sizeofoptionalheader;

	if (mulbuffer[0] != 'P' && mulbuffer[1] != 'E' && mulbuffer[2] != '\0' && mulbuffer[3] != '\0') {
		data_container.dosheader.e_magic = (mulbuffer[0] << 24) | (mulbuffer[1] << 16) | (mulbuffer[2] << 8) | mulbuffer[3];
		result.isvalid = false;
		result.issuspicious = true;
		data_container.structures_attributes.file_header_normal_ = false;
		result.field_anomalies_.push_back("PE 签名验证失败，不是有效的PE文件。");
		result.warnings_.push_back("PE 签名字段异常。");
		result.informations_.push_back("【异常】PE签名异常，期望值：0x00004550。");
	}

	/* 偏移检查 */
	if (shared_structure.peheader_offset_ < 0x40) {
		data_container.structures_attributes.file_header_normal_ = false;
		result.excursion_anomalies_.push_back("检测到File Header（文件头）偏移异常。");
		result.warnings_.push_back("File Header（文件头）偏移存在重叠。");
		result.informations_.push_back("【异常】期望的文件头偏移值：大于0x40。");
	}
	/* 架构字段检查 */
	if (shared_structure.machine_ == 0x0000) {
		data_container.structures_attributes.file_header_normal_ = false;
		result.field_anomalies_.push_back("machine字段异常。");
		result.informations_.push_back("【异常】machine字段为空。");
	}
	result.informations_.push_back(field_interpretation(shared_structure.machine_));
	/* 节区数量字段检查，实际数量检查的对照手段在函数 section_headers_analisis() 中 */
	if (shared_structure.number_of_sections_ == 0) {
		shared_structure.number_of_sections_isvalid_ = EleCorrectness::not_valid;
		data_container.structures_attributes.file_header_normal_ = false;
		result.field_anomalies_.push_back("fileheader -> numberofsections字段异常。");
		result.informations_.push_back("【异常】逻辑定义的节区数量为0。");
	}
	else if (shared_structure.number_of_sections_ > 96) {
		shared_structure.number_of_sections_isvalid_ = EleCorrectness::uncertain;
		data_container.structures_attributes.file_header_normal_ = false;
		result.field_anomalies_.push_back("fileheader -> numberofsections字段异常。");
		result.informations_.push_back("【异常】逻辑定义的节区数量过多，可能为混淆手段。");
	}
	/* sizeofoptionalheader字段检查 */
	if (shared_structure.size_of_optionalheader_ != 0xF0 && shared_structure.size_of_optionalheader_ != 0xE0) {
		data_container.structures_attributes.file_header_normal_ = false;
		result.field_anomalies_.push_back("fileheader -> sizeofoptionalheader字段异常。");
		result.informations_.push_back("【异常】sizeofoptionalheader字段值非标准值。");
	}
	data_container.diarelist.push_back(result);
	return true;
}

bool PEanalyzer::optional_header_analysis() {
	/* 初始化 */
	Diaresults result;
	int headerlength = 222;

	shared_structure.magic_ = (mulbuffer[read_offset] << 8) | mulbuffer[read_offset + 1];
	read_offset += 2;
	/* 架构确定、magic字段验证 */
	result.component_name_ = "Optional Header";
	result.component_type_ = "header";
	result.file_offset_ = shared_structure.peheader_offset_ + 20;
	result.data_size_ = headerlength + 2;

	/* 分类填充、imagebase值判断 */
	if (shared_structure.bitness_ == 32) { // 32位
		if (read_offset >= 0 && read_offset < 5600) {
			std::memcpy(&data_container.optionalheader32,
				mulbuffer + read_offset,
				sizeof(IMAGE_OPTIONAL_HEADER32));
			read_offset += sizeof(IMAGE_OPTIONAL_HEADER32);
		}
		
		shared_structure.address_of_entrypoint_ = data_container.optionalheader32.AddressOfEntryPoint;
		shared_structure.imagebase32_ = data_container.optionalheader32.ImageBase;
		shared_structure.section_alignment_ = data_container.optionalheader32.SectionAlignment;
		shared_structure.file_alignment_ = data_container.optionalheader32.FileAlignment;
		shared_structure.size_of_image_ = data_container.optionalheader32.SizeOfImage;
		shared_structure.import_table_RVA_ = data_container.optionalheader32.DataDirectory[1].VirtualAddress;
		shared_structure.import_table_size_ = data_container.optionalheader32.DataDirectory[1].Size;
		shared_structure.relocation_table_RVA_ = data_container.optionalheader32.DataDirectory[5].VirtualAddress;
		shared_structure.relocation_table_size_ = data_container.optionalheader32.DataDirectory[5].Size;
		shared_structure.tls_table_RVA_ = data_container.optionalheader32.DataDirectory[9].VirtualAddress;
		shared_structure.tls_table_size_ = data_container.optionalheader32.DataDirectory[9].Size;

		shared_structure.size_of_headers_ = data_container.optionalheader32.SizeOfHeaders;

		if (shared_structure.imagebase32_ == 0) {
			shared_structure.image_base_isvalid_ = EleCorrectness::not_valid;
			data_container.structures_attributes.optional_header_normal_ = false;
			result.field_anomalies_.push_back("optionalheader->imagebase（预设加载基址）字段异常。");
			result.warnings_.push_back("optionalheader->imagebase字段存在篡改，无效字段。");
			result.informations_.push_back("【异常】optionalheader->imagebase（预设加载基址）字段为0。");
		}
		else if (shared_structure.imagebase32_ >= 0xFFFFFFFF) {
			shared_structure.image_base_isvalid_ = EleCorrectness::not_valid;
			data_container.structures_attributes.optional_header_normal_ = false;
			result.field_anomalies_.push_back("optionalheader->imagebase（预设加载基址）字段异常。");
			result.warnings_.push_back("optionalheader->imagebase字段存在篡改，无效字段。");
			result.informations_.push_back("【异常】optionalheader->imagebase（预设加载基址）超过32位地址空间上限。");
		}
	}
	else if (shared_structure.bitness_ == 64) { // 64位
		if (read_offset >= 0 && read_offset < 5600) {
			std::memcpy(&data_container.optionalheader64,
				mulbuffer + read_offset,
				sizeof(IMAGE_OPTIONAL_HEADER64));
			read_offset += sizeof(IMAGE_OPTIONAL_HEADER64);
		}
		
		shared_structure.address_of_entrypoint_ = data_container.optionalheader64.AddressOfEntryPoint;
		shared_structure.imagebase64_ = data_container.optionalheader64.ImageBase;
		shared_structure.section_alignment_ = data_container.optionalheader64.SectionAlignment;
		shared_structure.file_alignment_ = data_container.optionalheader64.FileAlignment;
		shared_structure.size_of_image_ = data_container.optionalheader64.SizeOfImage;
		shared_structure.import_table_RVA_ = data_container.optionalheader64.DataDirectory[1].VirtualAddress;
		shared_structure.import_table_size_ = data_container.optionalheader64.DataDirectory[1].Size;
		shared_structure.relocation_table_RVA_ = data_container.optionalheader64.DataDirectory[5].VirtualAddress;
		shared_structure.relocation_table_size_ = data_container.optionalheader64.DataDirectory[5].Size;
		shared_structure.tls_table_RVA_ = data_container.optionalheader64.DataDirectory[9].VirtualAddress;
		shared_structure.tls_table_size_ = data_container.optionalheader64.DataDirectory[9].Size;

		shared_structure.size_of_headers_ = data_container.optionalheader64.SizeOfHeaders;

		if (shared_structure.imagebase64_ <= 0x100000 || shared_structure.imagebase64_ >= 0x7FFF00000000) {
			shared_structure.image_base_isvalid_ = EleCorrectness::not_valid;
			data_container.structures_attributes.optional_header_normal_ = false;
			result.field_anomalies_.push_back("optionalheader->imagebase（预设加载基址）字段异常。");
			result.warnings_.push_back("optionalheader->imagebase字段可能存在篡改。");
			result.informations_.push_back("【异常】optionalheadre->imagebase（预设加载基址）可能超过64位地址空间上限。");
		}
	}
	else if (shared_structure.bitness_ == 82) { // ROM
		data_container.crash_imformation_set(
			error_category::UNKNOWN_ERROR,
			"Optional Header（可选头）：暂不支持ROM架构的文件分析，敬请期待工具的未来更新！"
		);
		return false;

		if (read_offset >= 0 && read_offset < 5600) {
			std::memcpy(&data_container.optionalheaderrom,
				mulbuffer + read_offset,
				sizeof(IMAGE_ROM_OPTIONAL_HEADER));
			read_offset += sizeof(IMAGE_ROM_OPTIONAL_HEADER);
		}
		
		shared_structure.address_of_entrypoint_ = data_container.optionalheaderrom.AddressOfEntryPoint;
		shared_structure.base_of_code_ = data_container.optionalheaderrom.BaseOfCode;
		shared_structure.base_of_data_ = data_container.optionalheaderrom.BaseOfData;
		shared_structure.base_of_bss_ = data_container.optionalheaderrom.BaseOfBss;
		shared_structure.size_of_code_ = data_container.optionalheaderrom.SizeOfCode;
		shared_structure.size_of_initialized_data_ = data_container.optionalheaderrom.SizeOfInitializedData;
		shared_structure.size_of_uninitialized_data_ = data_container.optionalheaderrom.SizeOfUninitializedData;
		/* 暂定区域，ROM架构的字段处理 */
	}
	else {
		/* 暂定区域，实现magic字段检查失败时的处理，大致包括magic字段反推和预处理 */
		/* 可能关联的部分特殊函数和变量：joint_judge_magic()，shared_structure.advbitness_，shared_structure.bitness_ */
		shared_structure.bitness_ = 0;
		data_container.crash_imformation_set(
			error_category::UNKNOWN_ERROR,
			"Optional Header（可选头）：暂不支持magic字段的异常处理，敬请期待工具的未来更新！"
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
		if (shared_structure.file_alignment_ != 0x200) {
			if (shared_structure.file_alignment_ != 0 && ((shared_structure.file_alignment_ & (shared_structure.file_alignment_ - 1)) == 0)) {
				data_container.structures_attributes.optional_header_normal_ = false;
				result.informations_.push_back("【可疑】磁盘中节区数据的对齐粒度非常见值0x200。");
			}
			else {
				shared_structure.file_alignment_isvalid_ = EleCorrectness::not_valid;
				data_container.structures_attributes.optional_header_normal_ = false;
				result.field_anomalies_.push_back("optionalheader->filealignment（磁盘中节区数据的对齐粒度）字段异常。");
				result.warnings_.push_back("optionalheader->filealignment（磁盘中节区数据的对齐粒度）字段可能存在篡改。");
				result.informations_.push_back("【异常】optionalheader->filealignment（磁盘中节区数据的对齐粒度）非合法值。");
			}
		}

		/* section_alignment值检验 */
		if (shared_structure.section_alignment_ != 0x1000) {
			if (shared_structure.section_alignment_ != 0 && ((shared_structure.section_alignment_ & (shared_structure.section_alignment_ - 1)) == 0)) {
				data_container.structures_attributes.optional_header_normal_ = false;
				result.informations_.push_back("【可疑】optionalheader->sectionalignment(内存中节区数据的对齐粒度)非常见值0x1000。");
			}
			else {
				shared_structure.section_alignment_isvalid_ = EleCorrectness::not_valid;
				data_container.structures_attributes.optional_header_normal_ = false;
				result.field_anomalies_.push_back("optionalheader->sectionalignment（内存中节区数据的对齐粒度）字段异常。");
				result.warnings_.push_back("optionalheader->sectionalignment（内存中节区数据的对齐粒度）字段可能存在篡改。");
				result.informations_.push_back("【异常】optionalheader->sectionalignment（内存中节区数据的对齐粒度）非合法值。");
			}
		}

		/* file_alignment、section_alignment联合检验 */
		if (shared_structure.file_alignment_isvalid_ == EleCorrectness::valid && shared_structure.section_alignment_isvalid_ == EleCorrectness::valid) {
			if (shared_structure.section_alignment_ < shared_structure.file_alignment_) {
				shared_structure.file_alignment_isvalid_ = EleCorrectness::not_valid;
				shared_structure.section_alignment_isvalid_ = EleCorrectness::not_valid;
				data_container.structures_attributes.optional_header_normal_ = false;
				result.field_anomalies_.push_back("格式异常：（optionalheader)sectionaliment < filealiment");
				result.warnings_.push_back("格式异常：（optionalheader)sectionaliment < filealiment");
				result.informations_.push_back("【异常】（optionalheader)sectionaliment < filealiment，不符合规范格式。");
			}
			else if (shared_structure.section_alignment_ == shared_structure.file_alignment_) {
				data_container.structures_attributes.optional_header_normal_ = false;
				result.informations_.push_back("【可疑】磁盘和内存对齐粒度过于整齐。");
			}
		}
		else {
			data_container.structures_attributes.optional_header_normal_ = false;
			shared_structure.file_alignment_isvalid_ = EleCorrectness::uncertain;
			shared_structure.section_alignment_isvalid_ = EleCorrectness::uncertain;
		}

		/* address_of_entrypoint值检验 */
		if (shared_structure.address_of_entrypoint_ == 0) {
			shared_structure.address_of_entrypoint_isvalid_ = EleCorrectness::not_valid;
			data_container.structures_attributes.optional_header_normal_ = false;
			result.field_anomalies_.push_back("optionalheader->addressofentrypoint（入口点RVA）字段异常。");
			result.warnings_.push_back("optionalheader->addressofentrypoint（入口点RVA）字段存在篡改，无效字段。");
			result.informations_.push_back("【异常】optionalheader->addressofentrypoint（入口点RVA）字段为0。");
		}
		/*节对齐验证需要结合file和sectionalignment计算
		节区验证需要知道节区具体位置
		地址计算需要结合imagebase
		此处暂时不验证*/

		/* size_of_image值检验 */
		if (shared_structure.section_alignment_isvalid_ == EleCorrectness::not_valid) {
			data_container.structures_attributes.optional_header_normal_ = false;
			shared_structure.size_of_image_isvalid_ = EleCorrectness::uncertain;
		}
		else if (shared_structure.size_of_image_ % shared_structure.section_alignment_ != 0) {
			shared_structure.size_of_image_isvalid_ = EleCorrectness::not_valid;
			data_container.structures_attributes.optional_header_normal_ = false;
			result.field_anomalies_.push_back("optionalheader->sizeofimage（映像在内存中的总大小）值异常。");
			result.warnings_.push_back("optionalheader->sizeofimage（映像在内存中的总大小）字段存在篡改，无效字段。");
			result.informations_.push_back("【异常】optionalheader->sizeofimage（映像在内存中的总大小）值非对齐值倍数。");
		}

		/* address_of_entrypoint、size_of_image联合检验 */
		if (shared_structure.address_of_entrypoint_ >= shared_structure.size_of_image_ && shared_structure.size_of_image_isvalid_ == EleCorrectness::valid) {
			shared_structure.address_of_entrypoint_isvalid_ = EleCorrectness::not_valid;
			data_container.structures_attributes.optional_header_normal_ = false;
			result.field_anomalies_.push_back("optionalheader->addressofentrypoint（入口点RVA）字段异常。");
			result.warnings_.push_back("optionalheader->addressofentrypoint（入口点RVA）字段存在篡改，无效字段。");
			result.informations_.push_back("【异常】optionalheader->addressofentrypoint（入口点RVA）超出映像在内存中的总大小。");
		}
		/* 暂定区域：addressofentrypoint指向的节区验证 */
		/* addressofentrypoint指向的节区属性合法性验证 */
		/* AddressOfEntryPoint + ImageBase验证入口点的绝对内存地址是否有效。等，*/
		/* 暂定区域：以上字段分析以及，长度计算，以及，延迟导入分析 */

		/* dataderectory[1]值检验 */
		if (shared_structure.import_table_RVA_ == 0) {
			result.informations_.push_back("【普通】无导入表。");
		}
		else {
			if (shared_structure.import_table_size_ == 0) {
				data_container.structures_attributes.optional_header_normal_ = false;
				result.field_anomalies_.push_back("optionalheader->dataderectory[1]->Size（导入表大小）字段异常");
				result.warnings_.push_back("optionalheader->dataderectory[1]->Size（导入表大小）字段存在篡改，无效字段");
				result.informations_.push_back("【异常】optionalheader->dataderectory[1]->Size（导入表大小）与RVA值不一致");
			}
		}
		if (shared_structure.import_table_RVA_ < 0x1000 || shared_structure.import_table_RVA_ > 0x7FFFFFFF) {
			data_container.structures_attributes.optional_header_normal_ = false;
			result.field_anomalies_.push_back("optionalheader->dataderectory[1]->VirtualAddress（导入表RVA）字段异常");
			result.warnings_.push_back("optionalheader->dataderectory[1]->VirtualAddress（导入表RVA）字段存在篡改，无效字段");
			result.informations_.push_back("【异常】optionalheader->dataderectory[1]->VirtualAddress（导入表RVA）超出映像在内存中的总大小");
		}
		if ((shared_structure.import_table_RVA_ & 0x3) != 0) {
			data_container.structures_attributes.optional_header_normal_ = false;
			result.informations_.push_back("【可疑】optionalheader->dataderectory[1]->VirtualAddress（导入表RVA）未按4字节对齐");
		}

		/* dataderectory[5]值检验 */
		if (shared_structure.relocation_table_RVA_ == 0) {
			data_container.structures_attributes.optional_header_normal_ = false;
			result.informations_.push_back("【普通】dataderectory[5]==0，无显式重定位表。");
		}
		else {
			if (shared_structure.relocation_table_size_ == 0) {
				data_container.structures_attributes.optional_header_normal_ = false;
				result.field_anomalies_.push_back("optionalheader->dataderectory[5]->Size（重定位表大小）字段异常");
				result.warnings_.push_back("optionalheader->dataderectory[5]->Size（重定位表大小）字段存在篡改，无效字段");
				result.informations_.push_back("【异常】optionalheader->dataderectory[5]->Size（重定位表大小）与RVA值不一致");
			}
		}
		if (shared_structure.relocation_table_RVA_ < 0x1000 || shared_structure.import_table_RVA_ > 0x7FFFFFFF) {
			data_container.structures_attributes.optional_header_normal_ = false;
			result.field_anomalies_.push_back("optionalheader->dataderectory[5]->VirtualAddress（导入表RVA）字段异常");
			result.warnings_.push_back("optionalheader->dataderectory[5]->VirtualAddress（导入表RVA）字段存在篡改，无效字段");
			result.informations_.push_back("【异常】optionalheader->dataderectory[5]->VirtualAddress（导入表RVA）超出映像在内存中的总大小");
		}
		if ((shared_structure.relocation_table_RVA_ & 0x3) != 0) {
			data_container.structures_attributes.optional_header_normal_ = false;
			result.informations_.push_back("【可疑】optionalheader->dataderectory[5]->VirtualAddress（导入表RVA）未按4字节对齐");
		}

		/* dataderectory[9]值检验 */
		if (shared_structure.tls_table_RVA_ == 0) {
			result.informations_.push_back("【普通】dataderectory[9]==0，无显式TLS表。");
		}
		else {
			if (shared_structure.tls_table_size_ == 0) {
				data_container.structures_attributes.optional_header_normal_ = false;
				result.field_anomalies_.push_back("optionalheader->dataderectory[9]->Size（TLS表大小）字段异常");
				result.warnings_.push_back("optionalheader->dataderectory[9]->Size（TLS表大小）字段存在篡改，无效字段");
				result.informations_.push_back("【异常】optionalheader->dataderectory[9]->Size（TLS表大小）与RVA值不一致");
			}
		}
		if (shared_structure.tls_table_RVA_ < 0x1000 || shared_structure.import_table_RVA_ > 0x7FFFFFFF) {
			data_container.structures_attributes.optional_header_normal_ = false;
			result.field_anomalies_.push_back("optionalheader->dataderectory[9]->VirtualAddress（TLS表RVA）字段异常");
			result.warnings_.push_back("optionalheader->dataderectory[9]->VirtualAddress（TLS表RVA）字段存在篡改，无效字段");
			result.informations_.push_back("【异常】optionalheader->dataderectory[9]->VirtualAddress（TLS表RVA）超出映像在内存中的总大小");
		}
		if ((shared_structure.tls_table_RVA_ & 0x3) != 0) {
			data_container.structures_attributes.optional_header_normal_ = false;
			result.informations_.push_back("【可疑】optionalheader->dataderectory[9]->VirtualAddress（TLS表RVA）未按4字节对齐");
		}
	}
	data_container.diarelist.push_back(result);
	return true;
}

bool PEanalyzer::section_headers_analysis() {
	Diaresults result;
	int i = 0;

	result.component_name_ = "Section Header";
	result.component_type_ = "header";
	result.file_offset_ = shared_structure.peheader_offset_ + 20 + data_container.diarelist[3].data_size_;
	
	size_t read_offset_copy = read_offset;
	int section_error_status_code = 0; // 参考 database.cpp -> is_this_section_valid() 函数的返回值定义

	// 基于宽松条件首次扫描节区数量（shared_structure.detected_section_count_）
	// 这里主要是避免相信numberofsections造成的可能的漏判
	for (; i < REASONABLE_MAX_SECTIONS; i++) {
		IMAGE_SECTION_HEADER current_section = {};

		if (read_offset >= 0 && read_offset < 5600) {
			std::memcpy(&current_section,
				mulbuffer + read_offset,
				sizeof(IMAGE_SECTION_HEADER));
		}
		else {
			try {
				throw std::out_of_range("(sectionheader)临时分析缓冲区读取复用缓冲区时偏移异常。");
			}
			catch (const std::out_of_range& e) {
				data_container.crash_imformation_set(
					error_category::OFFSET_OUT_OF_RANGE,
					"Section Header（节区头）：临时分析缓冲区读取复用缓冲区时偏移异常。"
				);
				data_container.diarelist.push_back(result);
				return false;
			}
		}

		if (is_this_section_valid(current_section) == 0) {
			read_offset += sizeof(IMAGE_SECTION_HEADER);
			// result.data_size_ += 40;
			shared_structure.detected_section_count_ += 1;
			// data_container.sectionheaders.push_back(current_section);
			continue;
		}
		section_error_status_code = is_this_section_valid(current_section);
		break;
	}
	// 节区因前面字段错误而导致无法扫描，此处直接中止分析节区头部分，仅输出至可选头分析结果
	if (data_container.output_range < 5) { 
		return true;
	}

	// 数量矛盾判断与重置
	bool has_contradiction = true;
	int max_num = shared_structure.detected_section_count_;
	int theoretical_max_sections = (shared_structure.size_of_headers_ - (result.file_offset_)) / 40;
	if (shared_structure.number_of_sections_ == shared_structure.detected_section_count_ &&
	shared_structure.detected_section_count_ <= theoretical_max_sections) {
		has_contradiction = false;
	}
	if (section_error_status_code != 6 && has_contradiction) {
		if (theoretical_max_sections > max_num) { max_num = theoretical_max_sections; }
		if (shared_structure.number_of_sections_ > max_num) { max_num = shared_structure.number_of_sections_; }
	}   // 如果是因为扫描到全零节区头而停止扫描的，可认为是扫描正常结束，不进行数量重置
	if (section_error_status_code == 6 && max_num == 0) {
		max_num = shared_structure.number_of_sections_ != 0 ? shared_structure.number_of_sections_ : theoretical_max_sections;
	}   // 排除恶意构造的第一个节区全0导致扫描器崩溃情况

	// 基于严格条件重复扫描进行异常分析
	read_offset = read_offset_copy; // 重置read_offset
	for (size_t j = 0; j < max_num; j++) {
		if (j == REASONABLE_MAX_SECTIONS) {
			result.informations_.insert(result.informations_.begin(), "检测到可能的节区头数量过多，工具将仅分析至前128个节区头。");
			data_container.max_number_of_possible_sections = j;
			break;
		}
		IMAGE_SECTION_HEADER current_section = {};

		if (read_offset >= 0 && read_offset < 5600) {
			std::memcpy(&current_section,
				mulbuffer + read_offset,
				sizeof(IMAGE_SECTION_HEADER));
		}
		else {
			try {
				throw std::out_of_range("(sectionheader)临时分析缓冲区读取复用缓冲区时偏移异常。");
			}
			catch (const std::out_of_range& e) {
				data_container.crash_imformation_set(
					error_category::OFFSET_OUT_OF_RANGE,
					"Section Header（节区头）：临时分析缓冲区读取复用缓冲区时偏移异常。"
				);
				data_container.diarelist.push_back(result);
				return false;
			}
		}

		SectionImformation section_imformation_element;
		data_container.section_attributes.push_back(section_imformation_element); // 创建记录节区属性的结构体
		section_characteristic_judge(current_section.Characteristics); // 根据characteristic判断节区展现的实际属性并存入结构体
		section_name_check(current_section.Name, current_section.Characteristics, result, j); // 检测Name字段，如果为常见值则标记可能属性，并与上述属性判断结果联合判断
		if (!data_container.section_attributes[j].known_combination_) {
			section_characteristic_check(current_section.Characteristics, result, j);
		} // 如果Name非常见值，则判断characteristic本身属性组合是否有问题

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
					throw std::runtime_error("SharedStructure->bitness值出错，无法读取偏移值。");
				}
			}
			catch (std::runtime_error& e) {
				data_container.output_range = 4;
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

		std::string msg1, msg2;

		// 内存区间乱序、重叠、空洞检查
		for (size_t j1 = 0; j1 < j; j1++) {
			// 内存分布重叠+乱序扫描
			int judgment_code = interval_relation_judgment(data_container.memory_interval_table[j1].begin, data_container.memory_interval_table[j1].end,
				data_container.memory_interval_table[j].begin, data_container.memory_interval_table[j].end);
			try {
				if (judgment_code == -1 || judgment_code == 0) {
					msg1 = "扫描至sectionheader[" + std::to_string(j) + "]处理内存区间情况时出现不合理计算范围或出现未知区间状态。";
					throw std::runtime_error(msg1);
				}
			}
			catch (std::runtime_error) {
				data_container.output_range = 4;
				break;
			}
			if (judgment_code == 2 || judgment_code == 3 || judgment_code == 4) { // 有重叠现象
				msg1 = "扫描至sectionheader[" + std::to_string(j) + "]内存映射区间时发现可能出现的内存映射重叠现象。";
				msg2 = "【可疑】sectionheader[" + std::to_string(j) + "]所示的映射区间与[" + std::to_string(j1) + "]所示节区出现重叠现象。";
				result.field_anomalies_.push_back(msg1);
				result.informations_.push_back(msg2);
			}
			if (judgment_code == 4 || judgment_code == 5) { // 有乱序现象
				msg1 = "扫描至sectionheader[" + std::to_string(j) + "]内存映射区间时发现可能出现的内存映射乱序现象。";
				msg2 = "【可疑】sectionheader[" + std::to_string(j) + "]所示的映射区间与[" + std::to_string(j1) + "]所示节区出现乱序现象。";
				result.field_anomalies_.push_back(msg1);
				result.informations_.push_back(msg2);
				data_container.m_orderliness = false;
			}
		}
		if (data_container.output_range < 5) {
			break;
		}
		// 内存区间排序
		if (max_num == j + 1 && !data_container.m_orderliness) {
			interval_insertion_sort(data_container.memory_interval_table);
		}
		if (max_num == j + 1 && !interval_hole_scan(data_container.memory_interval_table)) {
			result.field_anomalies_.push_back("sectionheader对应的节区在内存映射中可能存在空洞现象。");
			result.informations_.push_back("【可疑】sectionheader所示节区在内存中存在空洞现象。");
		}
		// 外存区间乱序、重叠、空洞检查
		for (size_t j2 = 0; j2 < j; j2++) {
			// 外存分布重叠+乱序扫描
			int judgment_code = interval_relation_judgment(data_container.storage_interval_table[j2].begin, data_container.storage_interval_table[j2].end,
				data_container.storage_interval_table[j].begin, data_container.storage_interval_table[j].end);
			try {
				if (judgment_code == -1 || judgment_code == 0) {
					msg1 = "扫描至sectionheader[" + std::to_string(j) + "]处理内存区间情况时出现不合理计算范围或出现未知区间状态。";
					throw std::runtime_error(msg1);
				}
			}
			catch (std::runtime_error) {
				data_container.output_range = 4;
				break;
			}
			if (judgment_code == 2 || judgment_code == 3 || judgment_code == 4) { // 有重叠现象
				msg1 = "扫描至sectionheader[" + std::to_string(j) + "]外存区间时发现可能出现的外存重叠现象。";
				msg2 = "【可疑】sectionheader[" + std::to_string(j) + "]所示的映射区间与[" + std::to_string(j2) + "]所示节区出现重叠现象。";
				result.field_anomalies_.push_back(msg1);
				result.informations_.push_back(msg2);
			}
			if (judgment_code == 4 || judgment_code == 5) { // 有乱序现象
				msg1 = "扫描至sectionheader[" + std::to_string(j) + "]外存区间时发现可能出现的外存乱序现象。";
				msg2 = "【可疑】sectionheader[" + std::to_string(j) + "]所示的外存区间与[" + std::to_string(j2) + "]所示节区出现乱序现象。";
				result.field_anomalies_.push_back(msg1);
				result.informations_.push_back(msg2);
				data_container.s_orderliness = false;
			}
		}
		if (data_container.output_range < 5) {
			break;
		}
		if (max_num == j + 1 && !data_container.s_orderliness) {
			interval_insertion_sort(data_container.storage_interval_table);
		}
		if (max_num == j + 1 && !interval_hole_scan(data_container.storage_interval_table)) {
			result.field_anomalies_.push_back("sectionheader对应的节区在文件可能出现空洞现象。");
			result.informations_.push_back("【可疑】sectionheader所示节区在文件中存在空洞现象。");
		}

		// 诊断异常区域


		// 诊断可疑区域
		if (current_section.VirtualSize < current_section.SizeOfRawData) {
			result.informations_.push_back("【可疑】VS < SRD");
		}
		//VirtualSize=0 但 SizeOfRawData>0
		if (data_container.section_attributes[j].known_combination_) {
			if (current_section.VirtualSize == 0 && current_section.SizeOfRawData > 0) {

			}
			result.informations_.push_back("【可疑】VS=0&&SRD>0");
			
		}

		read_offset += sizeof(IMAGE_SECTION_HEADER);
	}

}