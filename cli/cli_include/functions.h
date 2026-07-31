#pragma once

/* 前置声明 */
struct ScanResultsDistribution;

/*
 * ============================================================================
 * CLI 辅助函数模块 - 函数速查
 * ============================================================================
 * 
 * FUNCTIONS（函数）
 * - batch_statistiacl_output() 批量扫描统计结果输出
 * - show_help()                输出帮助信息
 * - show_version()             输出版本信息
 * 
 * ============================================================================
 */

void batch_statistiacl_output(ScanResultsDistribution& sr_distribution, int& total_files);

void show_help();

void show_version();