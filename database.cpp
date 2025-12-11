#include <vector>

#include "database.h"
#include "peanalyzer.h"

structuresults data_container;
extern SharedStructure shared_structure;

void structuresults::addresult(Diaresults input) {
	diarelist.push_back(input);
}

/* 节区字段的基础检查，后续再添加基于置信度的判断节区合法性的方法，相对于 section_headers_analisis() 函数仅做最低限度的可运行性检验 */
bool is_this_section_valid(const IMAGE_SECTION_HEADER& header) {
	// 1. Name字段简单验证
	for (size_t i = 0; i < 8; i++) {
		if (header.Name[i] == 0) {
			continue;
		}
		if (header.Name[i] < 0x20 || header.Name[i] > 0x7E) {
			return false;
		}
	}
	// 2. VirtualAddress 和 PointerToRawData 对齐检查
	if (shared_structure.section_alignment_isvalid_ == true) {
		if (header.VirtualAddress != 0 && header.VirtualAddress % shared_structure.section_alignment_ != 0) {
			return false;
		}
	}
	else {
		/* 暂定区域，section_alignment不合法导致无法检测的情况 */
	}
	if (shared_structure.file_alignment_isvalid_ == true) {
		if (header.PointerToRawData != 0 && header.PointerToRawData % shared_structure.file_alignment_ != 0) {
			return false;
		}
	}
	else {
		/* 暂定区域，file_alignment不合法导致无法检测的情况 */
	}
	// 3.SizeOfRawData 和 PointerToRawData 的一致性
	if (header.SizeOfRawData == 0) {
		if (header.PointerToRawData != 0) {
			return false;
		}
	}
	else {
		if (static_cast<uint64_t>(header.PointerToRawData) + static_cast<uint64_t>(header.SizeOfRawData) >= shared_structure.size_of_file_) {
			return false;
		}
	}
	// 4. 特征标志简单检查
	if (header.Characteristics == 0 || header.Characteristics == 0xFFFFFFFF) {
		return false;
	}
	
	return true;
}