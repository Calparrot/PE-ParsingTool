#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <type_traits>

#include "recheck_data.h"

/**
 * @brief 改进的整数聚类算法（带范围扩展）
 *
 * 将输入的一组整数按照指定粒度进行聚类，相邻且差值在粒度范围内的数值
 * 会被合并为一个范围。范围的起始值等于聚类中实际最小值，结束值等于
 * 聚类中实际最大值加上指定的扩展值。
 *
 * @tparam T 输入整数类型，必须是无符号整数类型
 * @param data 输入数据数组（会被排序和去重）
 * @param cluster_granularity 聚类粒度，默认值为10
 *                           相邻数值差值 <= cluster_granularity时会被归为一个范围
 * @param range_padding 范围扩展值，默认值为0
 *                      范围的end = 实际最大值 + range_padding
 * @return std::vector<RangeItem<T>> 聚类结果
 *
 * @throws std::invalid_argument 如果cluster_granularity为0
 *
 * 示例1:
 *   data = {1, 2, 4, 3, 6, 17, 20, 55, 89, 91, 93}
 *   cluster_granularity=10, range_padding=2
 *   聚类分组: {1,2,3,4,6}, {17,20}, {55}, {89,91,93}
 *   输出: [{1,8,range}, {17,22,range}, {55,55,point}, {89,95,range}]
 *   说明: 1-6扩展为1-8 (6+2), 17-20扩展为17-22 (20+2), 89-93扩展为89-95 (93+2)
 *
 * 示例2:
 *   data = {123, 134, 157, 158, 170, 222, 345, 777, 787, 900}
 *   cluster_granularity=50, range_padding=10
 *   聚类分组: {123,134,157,158,170}, {222}, {345}, {777,787}, {900}
 *   输出: [{123,180,range}, {222,222,point}, {345,345,point},
 *          {777,797,range}, {900,900,point}]
 */
template<typename T>
std::vector<RangeItem<T>> clusterIntegersWithPadding(
    std::vector<T>& data,
    T cluster_granularity = 10,
    T range_padding = 0) {

    // 静态断言：确保T是无符号整数类型
    static_assert(std::is_unsigned_v<T>, "T must be an unsigned integer type");

    // 参数验证
    if (cluster_granularity == 0) {
        throw std::invalid_argument("Cluster granularity must be greater than 0");
    }

    std::vector<RangeItem<T>> result;

    // 处理空输入
    if (data.empty()) {
        return result;
    }

    // 排序并去重
    std::sort(data.begin(), data.end());
    data.erase(std::unique(data.begin(), data.end()), data.end());

    // 聚类处理
    T cluster_min = data[0];  // 当前聚类的实际最小值
    T cluster_max = data[0];  // 当前聚类的实际最大值

    for (size_t i = 1; i < data.size(); ++i) {
        T diff = data[i] - data[i - 1];

        if (diff <= cluster_granularity) {
            // 当前值属于当前聚类，更新最大值
            cluster_max = data[i];
        }
        else {
            // 当前值超出粒度，结束上一个聚类
            if (cluster_min == cluster_max) {
                // 单点（没有范围扩展）
                result.emplace_back(cluster_min);
            }
            else {
                // 范围：begin=实际最小值，end=实际最大值+padding
                T range_end = cluster_max;
                // 检查加法溢出
                if (range_end > std::numeric_limits<T>::max() - range_padding) {
                    range_end = std::numeric_limits<T>::max();
                }
                else {
                    range_end += range_padding;
                }
                result.emplace_back(cluster_min, range_end, true);
            }

            // 开始新的聚类
            cluster_min = data[i];
            cluster_max = data[i];
        }
    }

    // 处理最后一个聚类
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

/**
 * @brief 便捷函数：不修改输入数据（const引用版本）
 */
template<typename T>
std::vector<RangeItem<T>> clusterIntegersWithPaddingConst(
    const std::vector<T>& input,
    T cluster_granularity = 10,
    T range_padding = 0) {
    std::vector<T> data = input;  // 复制数据
    return clusterIntegersWithPadding(data, cluster_granularity, range_padding);
}