#pragma once
#include <iostream>

/* 前置声明 */
struct ScanResultsDistribution;

// 输出批量扫描文件夹的统计结果
void batch_statistiacl_output(ScanResultsDistribution& sr_distribution, int& total_files);

// 输出帮助信息
void show_help();