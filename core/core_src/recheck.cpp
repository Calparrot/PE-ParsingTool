#include <string>
#include <vector>
#include <cstdint>

#include "database.h"
#include "recheck_data.h"

/* private */
bool ReInspector::check_data_nonempty(Structuresults& data_container) {
	if (data_container.structures_attributes.dos_header_normal_ == true &&
	!data_container.diarelist.empty()) {
		return true;
	}
	else {
		return false;
	}
}

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
	// ========== 匿名工具函数区 ==========

	// 不同节 RVA 转 RAW，输入为 RVA 数组，输出原地覆盖为 RAW 数组
	auto file_offset_calculate = [&](std::vector<uint32_t> &rva) -> std::vector<uint32_t> {
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
		} 
		while (i < rva.size());
		
		return rva; // 覆盖写入，其实现在已经转为 RAW
	};
	// ========== 结束 ==========

	std::vector<uint32_t> first_thunk_addr;
	std::vector<uint32_t> name_addr;
	for (size_t i = 0; i < data_container.import_descriptor.size(); i++) {
		first_thunk_addr.push_back(data_container.import_descriptor[i].OriginalFirstThunk);
		name_addr.push_back(data_container.import_descriptor[i].Name);
	}

	std::vector<RangeItem<uint32_t>> first_thunk_addr_clustering = cluster_int_pad(first_thunk_addr);
	std::vector<RangeItem<uint32_t>> name_addr_clustering = cluster_int_pad(name_addr);
	uint8_t buffer[8192] = { 0 }; // 8KB缓冲区

	return true;
}