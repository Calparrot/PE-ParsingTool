#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>
// 优化版使用 #include <unordered_map>

#include "database.h"
#include "recheck.h"
#include "recheck_data.h"

/* 非类成员工具函数 */
struct FirstThunkPoint {
	size_t module_idx; // 每个模块的索引
	uint32_t addr;     // 每个模块的INT地址
};

// [INT_extract/module_name_extract] 不同节 RVA 转 RAW，输入为 RVA 数组，输出原地覆盖为 RAW 数组
static void file_offset_calculate(std::vector<FirstThunkPoint>& point, Structuresults& data_container){
	int cached_section_index = -1; // 缓存上一次命中的节索引
	int idx = 0;                   // 正在转换的 rva 在数组的索引

	do {
		// 命中缓存
		if (cached_section_index >= 0 &&
			point[idx].addr >= data_container.memory_interval_table[cached_section_index].begin &&
			point[idx].addr < data_container.memory_interval_table[cached_section_index].end) {
			point[idx].addr = point[idx].addr
				+ data_container.storage_interval_table[cached_section_index].begin
				- data_container.memory_interval_table[cached_section_index].begin;
			idx++;
			continue;
		}
		// 未命中，遍历查找
		for (int temp = 0; temp < data_container.memory_interval_table.size(); temp++) {
			auto& range = data_container.memory_interval_table[temp];
			if (point[idx].addr >= range.begin && point[idx].addr < range.end) {
				cached_section_index = temp;
				point[idx].addr = point[idx].addr
					+ data_container.storage_interval_table[temp].begin
					- data_container.memory_interval_table[temp].begin;
				idx++;
				break;
			}
		}
	} while (idx < point.size());
};

// [INT_extract] INT数组划分函数（找到结尾并返回数组个数，不包含结尾全0数组）返回值0为查找失败，返回值1说明被缓冲区截断
static size_t INT_division(const uint8_t buffer[], size_t buffer_size, size_t offset, bool is_32bit) {
	if (buffer == nullptr || offset >= buffer_size) {
		return 0;
	}
	size_t thunk_size = is_32bit ? 4 : 8;
	size_t current_offset = offset;
	size_t count = 0;

	while (current_offset + thunk_size <= buffer_size) {
		uint64_t value = 0;
		const uint8_t* data_ptr = buffer + current_offset;
		if (is_32bit) {
			uint32_t val32 = 0;
			std::memcpy(&val32, data_ptr, 4);
			value = static_cast<uint64_t>(val32);
		}
		else {
			std::memcpy(&value, data_ptr, 8);
		}

		if (value == 0) {
			return count;
		}
		count++;
		current_offset += thunk_size;
	}
	return 1;
}

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
	bool is_32bit = (data_container.comprehensive_info_.file_identification_ == "32位");
	bool is_64bit = (data_container.comprehensive_info_.file_identification_ == "64位");
	if (!is_32bit && !is_64bit) {
		return false;
	}
	
	const size_t buffer_size = 8192;
	uint8_t buffer[buffer_size] = { 0 }; // 8KB 缓冲区

	std::vector<FirstThunkPoint> first_thunk_addr; // 带IMAGE_IMPORT_DESCRIPTOR顺序索引标记的OriginalFirstThunk原始数据
	first_thunk_addr.reserve(data_container.import_descriptor.size());
	for (size_t i = 0; i < data_container.import_descriptor.size(); i++) { // 先用原始RVA数据填充first_thunk_addr
		FirstThunkPoint temp_thunk_point = {};
		temp_thunk_point.module_idx = i;
		temp_thunk_point.addr = data_container.import_descriptor[i].OriginalFirstThunk;
		first_thunk_addr.push_back(temp_thunk_point);
	}
	file_offset_calculate(first_thunk_addr, data_container); // 再将 RVA 转 RAW
	std::sort(first_thunk_addr.begin(), first_thunk_addr.end(),
		[](const FirstThunkPoint& a, const FirstThunkPoint& b) {
			return a.addr < b.addr;  // 按地址升序排序
		});

	std::vector<uint32_t> t_first_thunk_addr; // 不带索引标记的OriginalFirstThunk转RAW数据
	t_first_thunk_addr.reserve(data_container.import_descriptor.size());
	for (size_t i = 0; i < data_container.import_descriptor.size(); i++) { // 用已经转好的RAW数据填充t_first_thunk_addr
		t_first_thunk_addr.push_back(first_thunk_addr[i].addr);
	}
	std::vector<RangeItem<uint32_t>> first_thunk_addr_clustering = cluster_int_pad(t_first_thunk_addr); // 聚类地址计算，减少文件IO次数

	size_t addr_idx = 0;
	for (size_t i = 0; i < first_thunk_addr_clustering.size(); i++) {
		std::fill(std::begin(buffer), std::end(buffer), 0);
		if (first_thunk_addr_clustering[i].is_range == true) { // 范围值
			uint32_t size = first_thunk_addr_clustering[i].end > first_thunk_addr_clustering[i].begin ?
				first_thunk_addr_clustering[i].end - first_thunk_addr_clustering[i].begin : 0;
			// 一个缓冲区可以读取完
			if (size != 0 && size <= buffer_size
			&& first_thunk_addr_clustering[i].end < data_container.comprehensive_info_.file_size_copy_) {
				pedata.seekg(first_thunk_addr_clustering[i].begin, std::ios::beg);
				if (!pedata) {
					return false;
				}
				pedata.read(reinterpret_cast<char*>(buffer), size);
				if (pedata.gcount() != size) {
					return false;
				}

				while (addr_idx < first_thunk_addr.size()) {
					if (first_thunk_addr[addr_idx].addr >= first_thunk_addr_clustering[i].begin
						&& first_thunk_addr[addr_idx].addr < first_thunk_addr_clustering[i].end) {
						size_t idx = first_thunk_addr[addr_idx].addr - first_thunk_addr_clustering[i].begin; // 已在if中检查，不用担心溢出风险
						size_t thunk_length = INT_division(buffer, buffer_size, idx, is_32bit);
						// ！！！暂未验证与考虑截断情况
						if (is_32bit) {
							auto& vec = recheck_container.in_module_info32_[addr_idx].IMAGE_THUNK_DATA32_;
							vec.clear();
							vec.resize(thunk_length);
							std::memcpy(vec.data(), buffer + idx, thunk_length * 4);
						}
						else {
							auto& vec = recheck_container.in_module_info64_[addr_idx].IMAGE_THUNK_DATA64_;
							vec.clear();
							vec.resize(thunk_length);
							std::memcpy(vec.data(), buffer + idx, thunk_length * 8);
						}
						addr_idx++;
					}
					else {
						break;
					}
				}
			}
			// 一个缓冲区读不下
			else {
				auto ceil_div = [](uint32_t pre_read_bytes, size_t buffer_size) -> size_t {
					return (static_cast<size_t>(pre_read_bytes) + buffer_size - 1) / buffer_size;
				};
				size_t buffers_num = ceil_div(size, buffer_size);

				for (size_t num = 0; num < buffers_num; num++) {
					if (first_thunk_addr_clustering[i].end < data_container.comprehensive_info_.file_size_copy_) {
						std::fill(std::begin(buffer), std::end(buffer), 0);
						pedata.seekg(first_thunk_addr_clustering[i].begin + (num * buffer_size), std::ios::beg);
						if (!pedata) {
							return false;
						}
						size_t read_size = first_thunk_addr_clustering[i].end - (num * buffer_size) > buffer_size ?
							buffer_size : first_thunk_addr_clustering[i].end - (num * buffer_size);
						pedata.read(reinterpret_cast<char*>(buffer), read_size);
						if (pedata.gcount() != read_size) {
							return false;
						}
					}
					else {
						return false;
					}

					while (addr_idx < first_thunk_addr.size()) {
						if (first_thunk_addr[addr_idx].addr >= first_thunk_addr_clustering[i].begin
							&& first_thunk_addr[addr_idx].addr < first_thunk_addr_clustering[i].end) {
							size_t idx = first_thunk_addr[addr_idx].addr - first_thunk_addr_clustering[i].begin - (num * buffer_size);
							size_t thunk_length = INT_division(buffer, buffer_size, idx, is_32bit);
							// ！！！暂未验证与考虑截断情况
							if (is_32bit) {
								auto& vec = recheck_container.in_module_info32_[addr_idx].IMAGE_THUNK_DATA32_;
								vec.clear();
								vec.resize(thunk_length);
								std::memcpy(vec.data(), buffer + idx, thunk_length * 4);
							}
							else {
								auto& vec = recheck_container.in_module_info64_[addr_idx].IMAGE_THUNK_DATA64_;
								vec.clear();
								vec.resize(thunk_length);
								std::memcpy(vec.data(), buffer + idx, thunk_length * 8);
							}
							addr_idx++;
						}
						else {
							break;
						}
					}
				}
			}
		}
		else { // 单点值
			pedata.seekg(first_thunk_addr_clustering[i].begin, std::ios::beg);
			if (!pedata) {
				return false;
			}
			pedata.read(reinterpret_cast<char*>(buffer), 1024);
			if (pedata.gcount() != 1024) {
				return false;
			}
			size_t thunk_length = INT_division(buffer, 1024, 0, is_32bit);
			if (is_32bit) {
				ImportModuleInfo32 module_info32;
				module_info32.IMAGE_THUNK_DATA32_.clear();
				module_info32.IMAGE_THUNK_DATA32_.resize(thunk_length);
				std::memcpy(module_info32.IMAGE_THUNK_DATA32_.data(), buffer, thunk_length * 4);
				recheck_container.in_module_info32_.push_back(module_info32);
			}
			else {
				ImportModuleInfo64 module_info64;
				module_info64.IMAGE_THUNK_DATA64_.clear();
				module_info64.IMAGE_THUNK_DATA64_.resize(thunk_length);
				std::memcpy(module_info64.IMAGE_THUNK_DATA64_.data(), buffer, thunk_length * 8);
				recheck_container.in_module_info64_.push_back(module_info64);
			}
			addr_idx++;
		}
	}
	return true;
}

bool ReInspector::module_name_extract(SecondaryRecord recheck_container, std::ifstream& pedata, Structuresults& data_container) {
	
	return true;
}