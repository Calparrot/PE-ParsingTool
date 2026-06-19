#include <iostream>

#include "functions.h"
#include "api.h"

void batch_statistiacl_output(ScanResultsDistribution& sr_distribution, int& total_files) {
    std::cout << "\n========================================\n";
    std::cout << "扫描完成：共成功分析 " << total_files << " 个文件\n";

    // 基础统计
    std::cout << "【基础统计】\n";
    std::cout << "共检测到信息数量: " << sr_distribution.info_num << std::endl;
    std::cout << "共检测到可疑数量: " << sr_distribution.suspicious_num << std::endl;
    std::cout << "共检测到警告数量: " << sr_distribution.warning_num << std::endl;
    std::cout << "共检测到错误数量: " << sr_distribution.error_num << std::endl;
    if (static_cast<double>(sr_distribution.suspicious_num) / static_cast<double>(total_files) >= 5 &&
    (static_cast<double>(sr_distribution.warning_num) + static_cast<double>(sr_distribution.error_num)) / static_cast<double>(total_files) >= 0.5){
		std::cout << "\n此批文件中异常项数平均值高于普通文件，可能存在特殊或异常文件。\n";
    }
    std::cout << std::endl;

    // 分布统计（只显示非零的）
    std::cout << "【扫描结果分布】\n";
    std::cout << "分布结果仅显示非零项，对应的索引含义按顺序依次为：\n";
    std::cout << "[VALUE_MISMATCH, INVALID_VALUE, EXCURSION_ANOMALY, ADDRESS_OUT_OF_RANGE, ABNORMAL_LENGTH, \n"
              << "STRUCTURE_MISSING, DETAILED_INFORMATION, REGULAR_ISSUE, INDEXED_ISSUE, RELATIONSHIP_ISSUE, ADDITIONAL_INFORMATION]\n"
	          << "更多具体索引含义请参照 diagnostic_codes.h 文件中的 Object 类定义\n\n";

    std::cout << "INFO 分布:\n";
    for (int i = 0; i < 20; i++) {
        if (sr_distribution.info_distribution[i] > 0) {
            std::cout << "  [" << i << "] = " << sr_distribution.info_distribution[i] << " ";
        }
    }

    std::cout << "\nSUSPICIOUS 分布:\n";
    for (int i = 0; i < 20; i++) {
        if (sr_distribution.suspicious_distribution[i] > 0) {
            std::cout << "  [" << i << "] = " << sr_distribution.suspicious_distribution[i] << " ";
        }
    }

    std::cout << "\nWARNING 分布:\n";
    for (int i = 0; i < 20; i++) {
        if (sr_distribution.warning_distribution[i] > 0) {
            std::cout << "  [" << i << "] = " << sr_distribution.warning_distribution[i] << " ";
        }
    }

    std::cout << "\nERROR 分布:\n";
    for (int i = 0; i < 20; i++) {
        if (sr_distribution.error_distribution[i] > 0) {
            std::cout << "  [" << i << "] = " << sr_distribution.error_distribution[i] << " ";
        }
    }

    std::cout << "\n类型分布：\n";
    for (int i = 0; i < 11; i++) {
        if (sr_distribution.type_distribution[i] > 0) {
            std::cout << "  [" << i << "] = " << sr_distribution.type_distribution[i] << " ";
        }
    }
    std::cout << std::endl;
}

void show_help() {
    std::cout << "用法: tool <命令> [参数]\n"
        << "\n命令:\n"
        << "  scan file <文件>         扫描单个文件\n"
        << "  scan folder <目录>       批量扫描文件夹\n"
        << "  export single -i <文件> -o <输出>  导出单文件报告\n"
        << "  export folder -i <目录> -o <输出>  批量导出报告\n"
        << "  -h, --help               显示帮助\n"
        << "\n示例:\n"
        << "  tool scan file a.exe\n"
        << "  tool scan folder ./samples\n";
}

void show_version() {
    std::cout << "PE_Parsing CLI 版本 0.0.0\n";
    std::cout << "其实都没有正式版本，功能还在开发中。\n" << std::endl;
}