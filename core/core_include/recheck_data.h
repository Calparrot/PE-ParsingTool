#pragma once
#include <vector>
#include <string>

/* 前置声明 */
struct Diaresults;

/* 结构体说明
	RangeItem         ：整数范围项，表示一个整数范围或单个整数，用于导入表地址简化读取，要求T为uint类型
	ImportModuleInfo32：32位 IMAGE_IMPORT_DESCRIPTOR 指向的Name和INT数据
	ImportModuleInfo64：64位 IMAGE_IMPORT_DESCRIPTOR 指向的Name和INT数据
*/
template<typename T>
struct RangeItem {
	T begin;        // 范围起始值（等于实际数据最小值）
	T end;          // 范围结束值（等于实际数据最大值 + pad）
	bool is_range;  // 是否为范围（true表示范围，false表示单点）

	RangeItem(T val) : begin(val), end(val), is_range(false) {}
	RangeItem(T b, T e, bool range) : begin(b), end(e), is_range(range) {}
};

struct ImportModuleInfo32 {
	std::string module_name_;
	std::vector<uint32_t> IMAGE_THUNK_DATA32_;
};

struct ImportModuleInfo64 {
	std::string module_name_;
	std::vector<uint64_t> IMAGE_THUNK_DATA64_;
};

/* 类说明
	SecondaryRecord：原Structuresults类增强版本
类成员说明
	re_diaresults_ ：单个结构复诊断结果
*/
class SecondaryRecord {
public:
	std::vector<Diaresults> rec_diaresults_{};
	
	std::vector<ImportModuleInfo32> in_module_info32_;
	std::vector<ImportModuleInfo64> in_module_info64_;
};

/*
    cluster_int_pad：整数聚类算法，参数中cluster_granularity为粒度大小，range_padding为结尾填充长度
 */
template<typename T>
std::vector<RangeItem<T>> cluster_int_pad(std::vector<T>& data, T cluster_granularity = 512, T range_padding = 512) {
    static_assert(std::is_unsigned_v<T>, "T must be an unsigned integer type");
    if (cluster_granularity == 0) {
        throw std::invalid_argument("Cluster granularity must be greater than 0");
    }

    std::vector<RangeItem<T>> result;
    if (data.empty()) {
        return result;
    }

    std::sort(data.begin(), data.end());
    data.erase(std::unique(data.begin(), data.end()), data.end());

    result.reserve(data.size());

    T cluster_min = data[0];  // 当前聚类的实际最小值
    T cluster_max = data[0];  // 当前聚类的实际最大值
    for (size_t i = 1; i < data.size(); ++i) {
        T diff = data[i] - data[i - 1];

        if (diff <= cluster_granularity) {
            cluster_max = data[i];
        }
        else {
            if (cluster_min == cluster_max) {
                result.emplace_back(cluster_min); // 单点
            }
            else {
                T range_end = cluster_max;        // 范围：begin=实际最小值，end=实际最大值+padding
                if (range_end > std::numeric_limits<T>::max() - range_padding) {
                    range_end = std::numeric_limits<T>::max();
                }
                else {
                    range_end += range_padding;
                }
                result.emplace_back(cluster_min, range_end, true);
            }
            cluster_min = data[i];
            cluster_max = data[i];
        }
    }

    if (cluster_min == cluster_max) {
        result.emplace_back(cluster_min);
    }
    else {
        T range_end = cluster_max;
        if (range_end > std::numeric_limits<T>::max() - range_padding) {
            range_end = std::numeric_limits<T>::max();
        }
        else {
            range_end += range_padding;
        }
        result.emplace_back(cluster_min, range_end, true);
    }

    return result;
}

template<typename T>
std::vector<RangeItem<T>> cluster_int_pad_const(const std::vector<T>& input, T cluster_granularity = 10, T range_padding = 0) {
    std::vector<T> data = input;
    return clusterIntegersWithPadding(data, cluster_granularity, range_padding);
}