#include <vector>

#include "database.h"
#include "peanalyzer.h"

structuresults data_container;
extern SharedStructure shared_structure{};

void structuresults::addresult(Diaresults input) {
	diarelist.push_back(input);
}

/* 先实现最基础的，后续再添加基于置信度的判断节区合法性的方法 */
bool is_this_section_valid(const IMAGE_SECTION_HEADER& header) {
	// 1. 名称基本检查
	for (size_t i = 0; i < 8; i++) {
		if (header.Name[i] == 0) {
			break;
		}
		if (header.Name[i] < 0x20 || header.Name[i] > 0x7E) {
			return false;
		}
	}
	// 2. 原始数据指针验证
	if (shared_structure.section_alignment_isvalid_ == true) {
		if (header.VirtualAddress % shared_structure.section_alignment_ != 0) {
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
	if (header.Characteristics == 0) {
		return false;
	}
	/*    （最重要的检查）
		if (header.SizeOfRawData > 0) {
			// 检查是否溢出
			if (header.PointerToRawData > UINT32_MAX - header.SizeOfRawData) {
				return false;
			}

			// 检查是否在文件范围内
			uint32_t raw_end = header.PointerToRawData + header.SizeOfRawData;
			if (header.PointerToRawData >= file_size || raw_end > file_size) {
				// 允许最后一个节区部分超出（文件截断情况）
				if (header.PointerToRawData >= file_size) {
					return false;
				}
			}
		}

		// 3. 虚拟地址和大小检查
		if (header.Misc.VirtualSize > 100 * 1024 * 1024) { // 100MB上限
			return false;
		}

		// 4. 特征标志检查
		if (header.Characteristics == 0 || header.Characteristics == 0xFFFFFFFF) {
			return false;
		}*/

	return true;
}