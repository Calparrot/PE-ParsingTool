#include <fstream>
#include <cstdint>
#include <sstream>
#include <cstring>

#include "peanalyzer.h"
#include "database.h"

#define REASONABLE_MAX_SECTIONS 128 // 节区头数量解析上限
/* constexpr int REASONABLE_MAX_SECTIONS = 128; C++ 11+标准*/

SharedStructure shared_structure{};
extern structuresults data_container;

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

void PEanalyzer::joint_judge_magic() {
	/* 暂定区域，实现magic字段错误时的预验证和反推 */
	/* 包括以下字段：machine、sizeofoptionalheader、datadirectory、imageBase、sectionalignment、filealignment、subsystem、characteristics、addressofentrypoint */
	/* 包括的验证方式：越界验证、节归属验证、对齐验证、编译器模式匹配等 */
}

void PEanalyzer::section_characteristic_check(uint32_t input_characteristic) {
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

void PEanalyzer::section_name_check(const uint8_t input_name[8], const uint32_t input_characteristic, Diaresults& inputresult) {
	static constexpr uint8_t TEXT[8] = { 0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00 };    // .text
	static constexpr uint8_t CODE[8] = { 0x2E, 0x63, 0x6F, 0x64, 0x65, 0x00, 0x00, 0x00 };    // .code
	static constexpr uint8_t ITEXT[8] = { 0x2E, 0x69, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00 };   // .itext
	static constexpr uint8_t DATA[8] = { 0x2E, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00 };    // .data
	static constexpr uint8_t RDATA[8] = { 0x2E, 0x72 ,0x64, 0x61, 0x74, 0x61, 0x00, 0x00 };   // .rdata
	static constexpr uint8_t IDATA[8] = { 0x2E, 0x69 ,0x64, 0x61, 0x74, 0x61, 0x00, 0x00 };   // .idata
	static constexpr uint8_t EDATA[8] = { 0x2E, 0x65 ,0x64, 0x61, 0x74, 0x61, 0x00, 0x00 };   // .edata
	static constexpr uint8_t BSS[8] = { 0x2E, 0x62, 0x73, 0x73, 0x00, 0x00, 0x00, 0x00 };     // .bss
	static constexpr uint8_t RSRC[8] = { 0x2E, 0x72, 0x73, 0x72, 0x63, 0x00, 0x00, 0x00 };    // .rsrc
	static constexpr uint8_t RELOC[8] = { 0x2E, 0x72, 0x65, 0x6C, 0x6F, 0x63, 0x00, 0x00 };   // .reloc
	static constexpr uint8_t DEBUG[8] = { 0x2E, 0x64, 0x65, 0x62, 0x75, 0x67, 0x24, 0x53 };   // .debug$S
	static constexpr uint8_t DRECTVE[8] = { 0x2E, 0x64, 0x72, 0x65, 0x63, 0x74, 0x76, 0x65 }; // .drectve
	static constexpr uint8_t TLS[8] = { 0x2E, 0x74, 0x6C, 0x73, 0x00, 0x00, 0x00, 0x00 };     // .tls
	static constexpr uint8_t PDATA[8] = { 0x2E, 0x70, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00 };   // .pdata
	static constexpr uint8_t XDATA[8] = { 0x2E, 0x78, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00 };   // .xdata

	bool judgement_set[7] = {};
	bool is_attribute_common = true;
	/*
	[0] bool mem_execute_;               // 内存可执行
    [1] bool mem_read_;                  // 内存可读
    [2] bool mem_write_;                 // 内存可写
    [3] bool mem_shared_;                // 内存共享
    [4] bool cnt_code_;                  // 包含可执行代码 
    [5] bool cnt_initialized_data_;      // 包含已初始化数据
    [6] bool cnt_uninitialized_data_;    // 零初始化
	*/

	if (memcmp(input_name, TEXT, 8) || memcmp(input_name, CODE, 8) || memcmp(input_name, ITEXT, 8)) {
		judgement_set[0] = true;
		judgement_set[1] = true;
		judgement_set[2] = false;
		judgement_set[4] = true;
		if (input_characteristic != 0x60000020) { is_attribute_common = false; }
	}
	else if (memcmp(input_name, DATA, 8)) {
		judgement_set[0] = false;
		judgement_set[1] = true;
		judgement_set[2] = true;
		judgement_set[5] = true;
		if (input_characteristic != 0xC0000040) { is_attribute_common = false; }
	}
	else if (memcmp(input_name, RDATA, 8) || memcmp(input_name, IDATA, 8) || memcmp(input_name, EDATA, 8)) {
		judgement_set[0] = false;
		judgement_set[1] = true;
		judgement_set[2] = false;
		judgement_set[5] = true;
		if (input_characteristic != 0x40000040) { is_attribute_common = false; }
	}
	else if (memcmp(input_name, BSS, 8)) {
		judgement_set[0] = false;
		judgement_set[1] = true;
		judgement_set[2] = true;
		judgement_set[6] = true;
		if (input_characteristic != 0xC0000080) { is_attribute_common = false; }
	}
	else if (memcmp(input_name, RSRC, 8)) {
		judgement_set[0] = false;
		judgement_set[1] = true;
		judgement_set[2] = false;
		judgement_set[5] = true;
		if (input_characteristic != 0x40000040) { is_attribute_common = false; }
	}
	else if (memcmp(input_name, RELOC, 8)) {
		judgement_set[0] = false;
		judgement_set[1] = true;
		judgement_set[2] = false;
		judgement_set[5] = true;
		if (input_characteristic != 0x42000040 
			&& input_characteristic != 0x40000040) { is_attribute_common = false; }
	}
	else if (memcmp(input_name, DEBUG, 8) || memcmp(input_name, DRECTVE, 8)) {
		judgement_set[0] = false;
		judgement_set[1] = true;
		judgement_set[2] = false;
		judgement_set[5] = true;
		if (input_characteristic != 0x42100040 
			&& input_characteristic != 0x40100040) { is_attribute_common = false; }
	}
	else if (memcmp(input_name, TLS, 8)) {
		judgement_set[0] = false;
		judgement_set[1] = true;
		judgement_set[2] = true;
		judgement_set[5] = true;
		if (input_characteristic != 0xC0000040) { is_attribute_common = false; }
	}
	else if (memcmp(input_name, PDATA, 8) || memcmp(input_name, XDATA, 8)) {
		judgement_set[0] = false;
		judgement_set[1] = true;
		judgement_set[2] = false;
		judgement_set[5] = true;
		if (input_characteristic != 0x40000040) { is_attribute_common = false; }
	}
	else {
		inputresult.field_anomalies_.push_back("sectionheader -> name 字段非常见编译器编译结果。");
	}
}

/* public函数 */
bool PEanalyzer::mzcheck() {
	clear_buffer();
	Diaresults result;
	pedata_.seekg(0, std::ios::beg); // 固定结构采用硬编码（beg），非固定结构采用动态偏移（cur）
	if (!pedata_) {
		result.warnings_.push_back("MZ Header（MZ签名）：文件流异常，文件指针移动失败，可能文件未正确打开或已损坏");
		data_container.addresult(result);
		return false;
	}
	pedata_.read(reinterpret_cast<char*>(mulbuffer), 2);
	if (pedata_.gcount() != 2) {
		result.warnings_.push_back("MZ Header（MZ签名）：文件流读取数据到内存缓冲区失败");
		data_container.addresult(result);
		return false;
	}

	result.component_name_ = "DOS Header -> MZ";
	result.component_type_ = "header";
	result.file_offset_ = 0;
	result.data_size_ = 2;

	if (mulbuffer[0] == 'M' && mulbuffer[1] == 'Z') {
		data_container.dosheader.e_magic = 0x4D5A;
		data_container.addresult(result);
	}
	else {
		data_container.dosheader.e_magic = (mulbuffer[0] << 8) | mulbuffer[1];
		result.field_anomalies_.push_back("不合法的MZ签名，不是有效的PE文件。");
		result.warnings_.push_back("MZ 签名字段异常。");
		result.informations_.push_back("【异常】MZ签名异常，期望值：0x4D5A。");
		data_container.addresult(result);
	}
	return true;
}

bool PEanalyzer::dosheader_analysis() {
	clear_buffer();
	Diaresults result;
	pedata_.seekg(2, std::ios::beg);
	if (!pedata_) {
		result.warnings_.push_back("DOS Header（DOS头）：文件流异常，文件指针移动失败，可能文件未正确打开或已损坏");
		data_container.addresult(result);
		return false;
	}
	pedata_.read(reinterpret_cast<char*>(mulbuffer), 62);
	if (pedata_.gcount() != 62) {
		result.warnings_.push_back("DOS Header（DOS头）：文件流读取数据到内存缓冲区失败");
		data_container.addresult(result);
		return false;
	}

	result.component_name_ = "DOS Header";
	result.component_type_ = "header";
	result.file_offset_ = 2;
	result.data_size_ = 62;

	std::memcpy(&data_container.dosheader, mulbuffer, sizeof(IMAGE_DOS_HEADER));
	shared_structure.peheader_offset_ = (mulbuffer[58] << 24) | (mulbuffer[59] << 16) | (mulbuffer[60] << 8) | mulbuffer[61];

	data_container.addresult(result);
	return true;
}

bool PEanalyzer::dosstub_analysis() {
	clear_buffer();
	Diaresults result;
	pedata_.seekg(64, std::ios::beg);
	if (!pedata_) {
		result.warnings_.push_back("DOS Stub（DOS存根）：文件流异常，文件指针移动失败，可能文件未正确打开或已损坏");
		data_container.addresult(result);
		return false;
	}
	int count = shared_structure.peheader_offset_ - 64 > 0 ? shared_structure.peheader_offset_ : 0;
	pedata_.read(reinterpret_cast<char*>(mulbuffer), count);
	if (pedata_.gcount() != count) {
		result.warnings_.push_back("DOS Stub（DOS存根）：文件流读取数据到内存缓冲区失败");
		data_container.addresult(result);
		return false;
	}

	result.component_name_ = "DOS Stub";
	result.component_type_ = "header";
	result.file_offset_ = 64;
	result.data_size_ = count;

	for (size_t i = 0; i < count; i++) {
		data_container.dosstub.push_back(mulbuffer[i]);
	}

	if (result.data_size_ >= 64 && result.data_size_ <= 128) {
		data_container.addresult(result);
		return true;
	}
	else {
		if (result.data_size_ == 0) {
			result.excursion_anomalies_.push_back("DOS存根（DOS Stub）区域缺失。");
		}
		else if (result.data_size_ <= 16) {
			result.excursion_anomalies_.push_back("DOS存根（DOS Stub）过短。");
		}
		else if (result.data_size_ <= 48) {
			result.excursion_anomalies_.push_back("DOS存根（DOS Stub）较短。");
		}
		else if (result.data_size_ <= 256) {
			result.excursion_anomalies_.push_back("DOS存根（DOS Stub）较长。");
		}
		else {
			result.excursion_anomalies_.push_back("DOS存根（DOS Stub）过长。");
		}
		result.warnings_.push_back("非标准DOS存根（DOS Stub）结构。");
		result.informations_.push_back("【存疑】DOS存根长度非标准，期望长度：约0x40字节");
		result.issuspicious = true;
		data_container.addresult(result);
		return true;
	}
}

bool PEanalyzer::signaturecheck() {
	clear_buffer();
	Diaresults result;
	pedata_.seekg(0, std::ios::cur);
	if (!pedata_) {
		result.warnings_.push_back("PEHeader（PE签名）：文件流异常，文件指针移动失败，可能文件未正确打开或已损坏");
		data_container.addresult(result);
		return false;
	}
	pedata_.read(reinterpret_cast<char*>(mulbuffer), 4);
	if (pedata_.gcount() != 4) {
		result.warnings_.push_back("PEHeader（PE签名）：文件流读取数据到内存缓冲区失败");
		data_container.addresult(result);
		return false;
	}

	result.component_name_ = "NT Header -> Signature";
	result.component_type_ = "header";
	result.file_offset_ = 64;
	result.data_size_ = 4;

	if (mulbuffer[0] == 'P' && mulbuffer[1] == 'E' && mulbuffer[2] == '\0' && mulbuffer[3] == '\0') {
		data_container.signature = 0x00004550;
	}
	else {
		data_container.dosheader.e_magic = (mulbuffer[0] << 24) | (mulbuffer[1] << 16) | (mulbuffer[2] << 8) | mulbuffer[3];
		result.isvalid = false;
		result.issuspicious = true;
		result.field_anomalies_.push_back("PE 签名验证失败，不是有效的PE文件。");
		result.warnings_.push_back("PE 签名字段异常。");
		result.informations_.push_back("【异常】PE签名异常，期望值：0x00004550。");
	}
	data_container.addresult(result);
	return true;
}

bool PEanalyzer::file_header_analysis() {
	clear_buffer();
	Diaresults result;
	pedata_.seekg(0, std::ios::cur);
	if (!pedata_) {
		result.warnings_.push_back("File Header（文件头）：文件流异常，文件指针移动失败，可能文件未正确打开或已损坏");
		data_container.addresult(result);
		return false;
	}
	pedata_.read(reinterpret_cast<char*>(mulbuffer), 20);
	if (pedata_.gcount() != 20) {
		result.warnings_.push_back("File Header（文件头）：文件流读取数据到内存缓冲区失败");
		data_container.addresult(result);
		return false;
	}

	result.component_name_ = "File Header";
	result.component_type_ = "header";
	result.file_offset_ = shared_structure.peheader_offset_;
	result.data_size_ = 20;

	std::memcpy(&data_container.fileheader, mulbuffer, sizeof(IMAGE_FILE_HEADER));
	shared_structure.machine_ = data_container.fileheader.machine;
	shared_structure.number_of_sections_ = data_container.fileheader.numberofsections;
	shared_structure.size_of_optionalheader_ = data_container.fileheader.sizeofoptionalheader;

	/* 偏移检查 */
	if (shared_structure.peheader_offset_ < 0x40) {
		result.excursion_anomalies_.push_back("检测到File Header（文件头）偏移异常。");
		result.warnings_.push_back("File Header（文件头）偏移存在重叠。");
		result.informations_.push_back("【异常】期望的文件头偏移值：大于0x40。");
	}
	/* 架构字段检查 */
	if (shared_structure.machine_ == 0x0000) {
		result.field_anomalies_.push_back("machine字段异常。");
		result.informations_.push_back("【异常】machine字段为空。");
	}
	result.informations_.push_back(field_interpretation(shared_structure.machine_));
	/* 节区数量字段检查，实际数量检查的对照手段在函数 section_headers_analisis() 中 */
	if (shared_structure.number_of_sections_ == 0) {
		shared_structure.number_of_sections_isvalid_ = false;
		result.field_anomalies_.push_back("fileheader -> numberofsections字段异常。");
		result.informations_.push_back("【异常】逻辑定义的节区数量为0。");
	}
	else if (shared_structure.number_of_sections_ > 96) {
		shared_structure.number_of_sections_isvalid_ = 2;
		result.field_anomalies_.push_back("fileheader -> numberofsections字段异常。");
		result.informations_.push_back("【异常】逻辑定义的节区数量过多，可能为混淆手段。");
	}
	/* sizeofoptionalheader字段检查 */
	if (shared_structure.size_of_optionalheader_ != 0xF0 && shared_structure.size_of_optionalheader_ != 0xE0) {
		result.field_anomalies_.push_back("fileheader -> sizeofoptionalheader字段异常。");
		result.informations_.push_back("【异常】sizeofoptionalheader字段值非标准值。");
	}
	data_container.addresult(result);
	return true;
}

bool PEanalyzer::optional_header_analysis() {
	/* 初始化 */
	clear_buffer();
	int headerlength = 222;
	Diaresults result;
	pedata_.seekg(2, std::ios::cur);
	if (!pedata_) {
		result.warnings_.push_back("optionalheader加载失败");
		data_container.addresult(result);
		return false;
	}
	pedata_.read(reinterpret_cast<char*>(mulbuffer), 2);
	if (pedata_.gcount() != 2) {
		result.warnings_.push_back("optionalheader加载失败");
		data_container.addresult(result);
		return false;
	}

	/* 架构确定、magic字段验证 */
	shared_structure.magic_ = (mulbuffer[0] << 8) | mulbuffer[1];
	magic_check(shared_structure.magic_, result, headerlength);
	pedata_.seekg(headerlength, std::ios::cur);
	if (!pedata_) {
		result.warnings_.push_back("optionalheader加载失败");
		data_container.addresult(result);
		return false;
	}
	pedata_.read(reinterpret_cast<char*>(mulbuffer) + 2, headerlength);
	if (pedata_.gcount() != headerlength) {
		result.warnings_.push_back("optionalheader加载失败");
		data_container.addresult(result);
		return false;
	}
	result.component_name_ = "Optional Header";
	result.component_type_ = "header";
	result.file_offset_ = shared_structure.peheader_offset_ + 20;
	result.data_size_ = headerlength + 2;

	/* 分类填充、imagebase值判断 */
	if (shared_structure.bitness_ == 32) { // 32位
		std::memcpy(&data_container.optionalheader32, mulbuffer, sizeof(IMAGE_OPTIONAL_HEADER32));
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

		if (shared_structure.imagebase32_ == 0) {
			shared_structure.image_base_isvalid_ = false;
			result.field_anomalies_.push_back("optionalheader->imagebase（预设加载基址）字段异常。");
			result.warnings_.push_back("optionalheader->imagebase字段存在篡改，无效字段。");
			result.informations_.push_back("【异常】optionalheader->imagebase（预设加载基址）字段为0。");
		}
		else if (shared_structure.imagebase32_ >= 0xFFFFFFFF) {
			shared_structure.image_base_isvalid_ = false;
			result.field_anomalies_.push_back("optionalheader->imagebase（预设加载基址）字段异常。");
			result.warnings_.push_back("optionalheader->imagebase字段存在篡改，无效字段。");
			result.informations_.push_back("【异常】optionalheader->imagebase（预设加载基址）超过32位地址空间上限。");
		}
	}
	else if (shared_structure.bitness_ == 64) { // 64位
		std::memcpy(&data_container.optionalheader64, mulbuffer, sizeof(IMAGE_OPTIONAL_HEADER64));
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

		if (shared_structure.imagebase64_ <= 0x100000 || shared_structure.imagebase64_ >= 0x7FFF00000000) {
			shared_structure.image_base_isvalid_ = false;
			result.field_anomalies_.push_back("optionalheader->imagebase（预设加载基址）字段异常。");
			result.warnings_.push_back("optionalheader->imagebase字段可能存在篡改。");
			result.informations_.push_back("【异常】optionalheadre->imagebase（预设加载基址）可能超过64位地址空间上限。");
		}
	}
	else if (shared_structure.bitness_ == 82) { // ROM
		std::memcpy(&data_container.optionalheaderrom, mulbuffer, sizeof(IMAGE_OPTIONAL_HEADER64));
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
	}

	/* x32、x64架构剩余字段处理 */
	if (shared_structure.bitness_ == 32 || shared_structure.bitness_ == 64) {
		/* magic字段一致性检验 */
		if (shared_structure.magic_isvalid_ == true) {
			/* 暂定区域，magic字段的一致性检验 */
			/* 可能关联的部分特殊函数和变量：magic_joint_check() */
		}

		/* file_alignment值检验 */
		if (shared_structure.file_alignment_ != 0x200) {
			if (shared_structure.file_alignment_ != 0 && ((shared_structure.file_alignment_ & (shared_structure.file_alignment_ - 1)) == 0)) {
				result.informations_.push_back("【可疑】磁盘中节区数据的对齐粒度非常见值0x200。");
			}
			else {
				shared_structure.file_alignment_isvalid_ = false;
				result.field_anomalies_.push_back("optionalheader->filealignment（磁盘中节区数据的对齐粒度）字段异常。");
				result.warnings_.push_back("optionalheader->filealignment（磁盘中节区数据的对齐粒度）字段可能存在篡改。");
				result.informations_.push_back("【异常】optionalheader->filealignment（磁盘中节区数据的对齐粒度）非合法值。");
			}
		}

		/* section_alignment值检验 */
		if (shared_structure.section_alignment_ != 0x1000) {
			if (shared_structure.section_alignment_ != 0 && ((shared_structure.section_alignment_ & (shared_structure.section_alignment_ - 1)) == 0)) {
				result.informations_.push_back("【可疑】optionalheader->sectionalignment(内存中节区数据的对齐粒度)非常见值0x1000。");
			}
			else {
				shared_structure.section_alignment_isvalid_ = false;
				result.field_anomalies_.push_back("optionalheader->sectionalignment（内存中节区数据的对齐粒度）字段异常。");
				result.warnings_.push_back("optionalheader->sectionalignment（内存中节区数据的对齐粒度）字段可能存在篡改。");
				result.informations_.push_back("【异常】optionalheader->sectionalignment（内存中节区数据的对齐粒度）非合法值。");
			}
		}

		/* file_alignment、section_alignment联合检验 */
		if (shared_structure.file_alignment_isvalid_ == true && shared_structure.section_alignment_isvalid_ == true) {
			if (shared_structure.section_alignment_ < shared_structure.file_alignment_) {
				shared_structure.file_alignment_isvalid_ = false;
				shared_structure.section_alignment_isvalid_ = false;
				result.field_anomalies_.push_back("格式异常：（optionalheader)sectionaliment < filealiment");
				result.warnings_.push_back("格式异常：（optionalheader)sectionaliment < filealiment");
				result.informations_.push_back("【异常】（optionalheader)sectionaliment < filealiment，不符合规范格式。");
			}
			else if (shared_structure.section_alignment_ == shared_structure.file_alignment_) {
				result.informations_.push_back("【可疑】磁盘和内存对齐粒度过于整齐。");
			}
		}
		else {
			shared_structure.file_alignment_isvalid_ = 2;
			shared_structure.section_alignment_isvalid_ = 2;
		}

		/* address_of_entrypoint值检验 */
		if (shared_structure.address_of_entrypoint_ == 0) {
			shared_structure.address_of_entrypoint_isvalid_ = false;
			result.field_anomalies_.push_back("optionalheader->addressofentrypoint（入口点RVA）字段异常。");
			result.warnings_.push_back("optionalheader->addressofentrypoint（入口点RVA）字段存在篡改，无效字段。");
			result.informations_.push_back("【异常】optionalheader->addressofentrypoint（入口点RVA）字段为0。");
		}
		/*节对齐验证需要结合file和sectionalignment计算
		节区验证需要知道节区具体位置
		地址计算需要结合imagebase
		此处暂时不验证*/

		/* size_of_image值检验 */
		if (shared_structure.section_alignment_isvalid_ == false) {
			shared_structure.size_of_image_isvalid_ = 2;
		}
		else if (shared_structure.size_of_image_ % shared_structure.section_alignment_ != 0) {
			shared_structure.size_of_image_isvalid_ = false;
			result.field_anomalies_.push_back("optionalheader->sizeofimage（映像在内存中的总大小）值异常。");
			result.warnings_.push_back("optionalheader->sizeofimage（映像在内存中的总大小）字段存在篡改，无效字段。");
			result.informations_.push_back("【异常】optionalheader->sizeofimage（映像在内存中的总大小）值非对齐值倍数。");
		}

		/* address_of_entrypoint、size_of_image联合检验 */
		if (shared_structure.address_of_entrypoint_ >= shared_structure.size_of_image_ && shared_structure.size_of_image_isvalid_ == true) {
			shared_structure.address_of_entrypoint_isvalid_ = false;
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
				result.field_anomalies_.push_back("optionalheader->dataderectory[1]->Size（导入表大小）字段异常");
				result.warnings_.push_back("optionalheader->dataderectory[1]->Size（导入表大小）字段存在篡改，无效字段");
				result.informations_.push_back("【异常】optionalheader->dataderectory[1]->Size（导入表大小）与RVA值不一致");
			}
		}
		if (shared_structure.import_table_RVA_ < 0x1000 || shared_structure.import_table_RVA_ > 0x7FFFFFFF) {
			result.field_anomalies_.push_back("optionalheader->dataderectory[1]->VirtualAddress（导入表RVA）字段异常");
			result.warnings_.push_back("optionalheader->dataderectory[1]->VirtualAddress（导入表RVA）字段存在篡改，无效字段");
			result.informations_.push_back("【异常】optionalheader->dataderectory[1]->VirtualAddress（导入表RVA）超出映像在内存中的总大小");
		}
		if ((shared_structure.import_table_RVA_ & 0x3) != 0) {
			result.informations_.push_back("【可疑】optionalheader->dataderectory[1]->VirtualAddress（导入表RVA）未按4字节对齐");
		}

		/* dataderectory[5]值检验 */
		if (shared_structure.relocation_table_RVA_ == 0) {
			result.informations_.push_back("【普通】无重定位表。");
		}
		else {
			if (shared_structure.relocation_table_size_ == 0) {
				result.field_anomalies_.push_back("optionalheader->dataderectory[5]->Size（重定位表大小）字段异常");
				result.warnings_.push_back("optionalheader->dataderectory[5]->Size（重定位表大小）字段存在篡改，无效字段");
				result.informations_.push_back("【异常】optionalheader->dataderectory[5]->Size（重定位表大小）与RVA值不一致");
			}
		}
		if (shared_structure.relocation_table_RVA_ < 0x1000 || shared_structure.import_table_RVA_ > 0x7FFFFFFF) {
			result.field_anomalies_.push_back("optionalheader->dataderectory[5]->VirtualAddress（导入表RVA）字段异常");
			result.warnings_.push_back("optionalheader->dataderectory[5]->VirtualAddress（导入表RVA）字段存在篡改，无效字段");
			result.informations_.push_back("【异常】optionalheader->dataderectory[5]->VirtualAddress（导入表RVA）超出映像在内存中的总大小");
		}
		if ((shared_structure.relocation_table_RVA_ & 0x3) != 0) {
			result.informations_.push_back("【可疑】optionalheader->dataderectory[5]->VirtualAddress（导入表RVA）未按4字节对齐");
		}

		/* dataderectory[9]值检验 */
		if (shared_structure.tls_table_RVA_ == 0) {
			result.informations_.push_back("【普通】无TLS表。");
		}
		else {
			if (shared_structure.tls_table_size_ == 0) {
				result.field_anomalies_.push_back("optionalheader->dataderectory[9]->Size（TLS表大小）字段异常");
				result.warnings_.push_back("optionalheader->dataderectory[9]->Size（TLS表大小）字段存在篡改，无效字段");
				result.informations_.push_back("【异常】optionalheader->dataderectory[9]->Size（TLS表大小）与RVA值不一致");
			}
		}
		if (shared_structure.tls_table_RVA_ < 0x1000 || shared_structure.import_table_RVA_ > 0x7FFFFFFF) {
			result.field_anomalies_.push_back("optionalheader->dataderectory[9]->VirtualAddress（TLS表RVA）字段异常");
			result.warnings_.push_back("optionalheader->dataderectory[9]->VirtualAddress（TLS表RVA）字段存在篡改，无效字段");
			result.informations_.push_back("【异常】optionalheader->dataderectory[9]->VirtualAddress（TLS表RVA）超出映像在内存中的总大小");
		}
		if ((shared_structure.tls_table_RVA_ & 0x3) != 0) {
			result.informations_.push_back("【可疑】optionalheader->dataderectory[9]->VirtualAddress（TLS表RVA）未按4字节对齐");
		}
	}
	data_container.addresult(result);
	return true;
}

bool PEanalyzer::section_headers_analisis() {
	Diaresults result;
	int i = 0;

	result.component_name_ = "Section Header";
	result.component_type_ = "header";
	result.file_offset_ = shared_structure.peheader_offset_;

	for (; i < REASONABLE_MAX_SECTIONS; i++) {
		clear_buffer();
		IMAGE_SECTION_HEADER current_section = {};
		pedata_.seekg(0, std::ios::cur);
		if (!pedata_) {
			result.warnings_.push_back("Section Header（节区头）：文件流异常，文件指针移动失败，可能文件未正确打开或已损坏");
			data_container.addresult(result);
			return false;
		}
		pedata_.read(reinterpret_cast<char*>(mulbuffer), 40);
		if (pedata_.gcount() != 40) {
			result.warnings_.push_back("Section Header（节区头）：文件流读取数据到内存缓冲区失败");
			data_container.addresult(result);
			return false;
		}

		std::memcpy(&current_section, mulbuffer, sizeof(IMAGE_SECTION_HEADER));
		if (is_this_section_valid(current_section)) {
			result.data_size_ += 40;
			shared_structure.detected_section_count_ += 1;
			data_container.sectionheaders.push_back(current_section);
			continue;
		}
		pedata_.seekg(-40, std::ios::cur);
		if (!pedata_) {
			result.warnings_.push_back("Section Header（节区头）：文件流异常，文件指针移动失败，可能文件未正确打开或已损坏");
			data_container.addresult(result);
			return false;
		}
		break;
	}
	try {
		if (i > 128) {
			throw std::length_error("检测到的实际节区数量过多，工具将仅分析至前128个节区。");
		}
	}
	catch (const std::length_error& e) {
		/* 暂定区域：仅处理前128个节区，后面显示二进制的情况 */

	}

	// fileheader -> numberofsections 和实际检测到节区的数量对照
	if (shared_structure.number_of_sections_ == shared_structure.detected_section_count_) {
		shared_structure.number_of_sections_isvalid_ = true;
	}
	else {
		shared_structure.number_of_sections_isvalid_ = false;
	}

	// 字段严格检查，相对于 is_this_section_valid() 函数属于混淆性检测
	for (size_t j = 0; j < shared_structure.detected_section_count_; j++) {
		// 记录节区属性
		section_imformation section_imformation_element;
		data_container.section_attributes.push_back(section_imformation_element);
		section_characteristic_check(data_container.sectionheaders[j].Characteristics);
		// Name 字段合法性检验
		section_name_check(data_container.sectionheaders[j].Name, data_container.sectionheaders[j].Characteristics, result);
	}
}