#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <type_traits>

#include "recheck_data.h"

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