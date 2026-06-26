#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>

#include "database.h"
#include "recheck.h"
#include "recheck_data.h"

/* 非类成员工具函数 */

// [INT_extract]不同节 RVA 转 RAW，输入为 RVA 数组，输出原地覆盖为 RAW 数组
static std::vector<uint32_t> file_offset_calculate(std::vector<uint32_t>& rva, Structuresults& data_container){
	int cached_section_index = -1; // 缓存上一次命中的节索引
	int idx = 0;                   // 正在转换的 rva 在数组的索引

	do {
		// 命中缓存
		if (cached_section_index >= 0 &&
			rva[idx] >= data_container.memory_interval_table[cached_section_index].begin &&
			rva[idx] < data_container.memory_interval_table[cached_section_index].end) {
			rva[idx] = rva[idx]
				+ data_container.storage_interval_table[cached_section_index].begin
				- data_container.memory_interval_table[cached_section_index].begin;
			idx++;
			continue;
		}
		// 未命中，遍历查找
		for (int temp = 0; temp < data_container.memory_interval_table.size(); temp++) {
			auto& range = data_container.memory_interval_table[temp];
			if (rva[idx] >= range.begin && rva[idx] < range.end) {
				cached_section_index = temp;
				rva[idx] = rva[idx]
					+ data_container.storage_interval_table[temp].begin
					- data_container.memory_interval_table[temp].begin;
				idx++;
				break;
			}
		}
	} while (idx < rva.size());

	return rva; // 覆盖写入，其实现在已经转为 RAW
};

/* ReInspector 类实现 */
/* public */
bool ReInspector::dosheader_recheck(Structuresults& data_container) {
	return true;
}

bool ReInspector::dosstub_recheck(Structuresults& data_container) {
	return true;
}

bool ReInspector::file_header_recheck(Structuresults& data_container) {
	return true;
}

bool ReInspector::optional_header_recheck(Structuresults& data_container) {
	return true;
}

bool ReInspector::section_headers_recheck(Structuresults& data_container) {
	return true;
}

bool ReInspector::INT_extract(SecondaryRecord recheck_container, std::ifstream& pedata, Structuresults& data_container) {
	if (!check_data_nonempty(data_container) ||
	!data_container.structures_attributes.import_descriptor_found_) {
		return false;
	}
	const size_t buffer_size = 8192;
	uint8_t buffer[buffer_size] = { 0 }; // 8KB 缓冲区

	std::vector<uint32_t> first_thunk_addr;
	for (size_t i = 0; i < data_container.import_descriptor.size(); i++) {
		first_thunk_addr.push_back(data_container.import_descriptor[i].OriginalFirstThunk);
	}
	file_offset_calculate(first_thunk_addr, data_container);

	std::vector<RangeItem<uint32_t>> first_thunk_addr_clustering = cluster_int_pad(first_thunk_addr);
	for (size_t i = 0; i < first_thunk_addr_clustering.size(); i++) {
		// 范围值
		if (first_thunk_addr_clustering[i].is_range == true) {
			std::fill(std::begin(buffer), std::end(buffer), 0);
			
			if (first_thunk_addr_clustering[i].end > first_thunk_addr_clustering[i].begin
			&& first_thunk_addr_clustering[i].end - first_thunk_addr_clustering[i].begin <= buffer_size
			&& first_thunk_addr_clustering[i].end < data_container.comprehensive_info_.file_size_copy_) {
				uint32_t size = first_thunk_addr_clustering[i].end - first_thunk_addr_clustering[i].begin;
				pedata.seekg(first_thunk_addr_clustering[i].begin, std::ios::beg);
				if (!pedata) {
					return false;
				}
				pedata.read(reinterpret_cast<char*>(buffer), size);
				if (pedata.gcount() != size) {
					return false;
				}
				for (size_t j = 0; j < first_thunk_addr.size(); j++) {
					if (first_thunk_addr[j] >= first_thunk_addr_clustering[i].begin
					&& first_thunk_addr[j] < first_thunk_addr_clustering[i].end) {
						if (data_container.comprehensive_info_.file_identification_ == "32位") {
							std::memcpy(&recheck_container.in_module_info32_[j].IMAGE_THUNK_DATA32_, buffer, 4);
						}
						else if (data_container.comprehensive_info_.file_identification_ == "64位") {
							std::memcpy(&recheck_container.in_module_info64_[j].IMAGE_THUNK_DATA64_, buffer, 8);
						}
						else {
							return false;
						}
					}
				}
			}
			else {
				return false;
			}
		}
		// 单点值
		else {
			pedata.seekg(first_thunk_addr_clustering[i].begin, std::ios::beg);
			if (!pedata) {
				return false;
			}
			pedata.read(reinterpret_cast<char*>(buffer), 8);
			if (pedata.gcount() != 8) {
				return false;
			}
			if (data_container.comprehensive_info_.file_identification_ == "32位") {
				ImportModuleInfo32 module_info32;
				std::memcpy(&module_info32, buffer, 4);
				recheck_container.in_module_info32_.push_back(module_info32);
			}
			else if (data_container.comprehensive_info_.file_identification_ == "64位") {
				ImportModuleInfo64 module_info64;
				std::memcpy(&module_info64, buffer, 8);
				recheck_container.in_module_info64_.push_back(module_info64);
			}
			else {
				return false;
			}
		}
	}

	return true;
}

bool ReInspector::module_name_extract(SecondaryRecord recheck_container, std::ifstream& pedata, Structuresults& data_container) {
	if (!check_data_nonempty(data_container) ||
		!data_container.structures_attributes.import_descriptor_found_) {
		return false;
	}
	const size_t buffer_size = 8192;
	uint8_t buffer[buffer_size] = { 0 }; // 8KB 缓冲区

	std::vector<uint32_t> name_addr;
	for (size_t i = 0; i < data_container.import_descriptor.size(); i++) {
		name_addr.push_back(data_container.import_descriptor[i].Name);
	}
	file_offset_calculate(name_addr, data_container);

	std::vector<RangeItem<uint32_t>> name_addr_clustering = cluster_int_pad(name_addr);

	for (size_t i = 0; i < name_addr_clustering.size(); i++) {
		// 范围值
		if (name_addr_clustering[i].end > name_addr_clustering[i].begin
			&& name_addr_clustering[i].end - name_addr_clustering[i].begin <= buffer_size
			&& name_addr_clustering[i].end < data_container.comprehensive_info_.file_size_copy_) {
			uint32_t size = name_addr_clustering[i].end - name_addr_clustering[i].begin;
			pedata.seekg(name_addr_clustering[i].begin, std::ios::beg);
			if (!pedata) {
				return false;
			}
			pedata.read(reinterpret_cast<char*>(buffer), size);
			if (pedata.gcount() != size) {
				return false;
			}
			for (size_t j = 0; j < name_addr.size(); j++) {
				if (name_addr[j] >= name_addr_clustering[i].begin
					&& name_addr[j] < name_addr_clustering[i].end) {
					if (data_container.comprehensive_info_.file_identification_ == "32位") {
						std::memcpy(&recheck_container.in_module_info32_[j].IMAGE_THUNK_DATA32_, buffer, 4);
					}
					else if (data_container.comprehensive_info_.file_identification_ == "64位") {
						std::memcpy(&recheck_container.in_module_info64_[j].IMAGE_THUNK_DATA64_, buffer, 8);
					}
					else {
						return false;
					}
				}
			}
		}
		// 单点值
		else {
			pedata.seekg(name_addr_clustering[i].begin, std::ios::beg);
			if (!pedata) {
				return false;
			}
			pedata.read(reinterpret_cast<char*>(buffer), 1024);
			if (pedata.gcount() != 1024) {
				return false;
			}
			if (data_container.comprehensive_info_.file_identification_ == "32位") {
				ImportModuleInfo32 module_info32;
				std::memcpy(&module_info32, buffer, 4);
				recheck_container.in_module_info32_.push_back(module_info32);
			}
			else if (data_container.comprehensive_info_.file_identification_ == "64位") {
				ImportModuleInfo64 module_info64;
				std::memcpy(&module_info64, buffer, 8);
				recheck_container.in_module_info64_.push_back(module_info64);
			}
			else {
				return false;
			}
		}
	}

	return true;
}