#include <vector>
#include <stdexcept>

#include "database.h"

// Structuresults data_container;

void Structuresults::crash_imformation_set(error_category code, const std::string& msg) {
	crashreport.error_code_ = code;
	crashreport.message_ = msg;
}

/* 节区头的基础检查，用于初步判断任意40字节是否为合法节区头，
   相对于 section_headers_analisis() 函数仅做较宽松的可能性检查，
   可能错判，不能作为最终输出结果 */

/* 函数返回值为错误状态码：
   0：合法节区头
   1：映射越界
   2：VirtualAddress未与SectionAlignment对齐
   3：PointerToRawData未与FileAlignment对齐
   4：VirtualAddress位于头内部
   5：PointerToRawData位于头内部
   6：关键字段全部为0
   7：（仅x32环境）VirtualAddress+VirtualSize超过32位系统内存页
*/
int is_this_section_valid(const SectionHeader& header, SharedStructure shared_structure, Structuresults data_container) {
	// Name字段全零验证
	bool all_zero_name = true;
	for (size_t i = 0; i < 8; i++) {
		if (header.Name[i] != 0) {
			all_zero_name = false;
			break;
		}
	}

	// 文件映射越界检测 PointerToRawData + SizeOfRawData > 文件大小
	if (header.SizeOfRawData > 0) {
		if (static_cast<uint64_t>(header.PointerToRawData) + static_cast<uint64_t>(header.SizeOfRawData) > static_cast<uint64_t>(data_container.comprehensive_info_.file_size_copy_)) {
			return 1;
		}
	}
	
	// VirtualAddress 和 PointerToRawData 对齐检查
	try {
		if (shared_structure.section_alignment_isvalid_ == EleCorrectness::valid) {
			if (header.VirtualAddress != 0 && header.VirtualAddress % shared_structure.section_alignment_ != 0) {
				return 2;
			}
		}
		else {
			// IMAGE_OPTIONAL_HEADER -> SectionAlignment值不合法，可能导致加载器报错，无法扫描节区头。
			throw std::runtime_error("IMAGE_OPTIONAL_HEADER -> The SectionAlignment value is invalid, \n\
				which may cause loader errors and prevent scanning of section headers.");
		}
		if (shared_structure.file_alignment_isvalid_ == EleCorrectness::valid) {
			if (header.PointerToRawData != 0 && header.PointerToRawData % shared_structure.file_alignment_ != 0) {
				return 3;
			}
		}
		else {
			// IMAGE_OPTIONAL_HEADER -> FileAlignment值不合法，可能导致加载器报错，无法扫描节区头。
			throw std::runtime_error("IMAGE_OPTIONAL_HEADER -> The FileAlignment value is invalid, \n\
				which may cause loader errors and prevent scanning of section headers.");
		}
	}
	catch (std::runtime_error& e) {
		// 不输出节区头和节区内容，后续也不处理
		data_container.num_of_scanned_blocks_ = 4;
	}

	// VirtualAddress 是否位于PE头区域检测
	if (header.VirtualAddress > 0 && header.VirtualAddress < shared_structure.size_of_headers_) {
		return 4;
	}

	// PointerToRawData 是否位于PE头区域检测
	if (header.PointerToRawData < shared_structure.size_of_headers_) {
		return 5;
	}

	// 关键字段全零检测
	if (all_zero_name &&
		header.VirtualSize == 0 &&
		header.VirtualAddress == 0 &&
		header.SizeOfRawData == 0 &&
		header.PointerToRawData == 0) {
		return 6;
	}

	// 特殊架构处理
	// VirtualSize 或 VirtualAddress导致地址溢出（32位系统）
	if (shared_structure.bitness_ == 32 && header.VirtualAddress + header.VirtualSize > 0xFFFFFFFF) {
		return 7;
	}

	return 0;
}

/* 置信度检测列表及其权重（%）*/
int file_confidence_detection(SharedStructure shared_structure) {
	int sum = 0;


	return sum;
}