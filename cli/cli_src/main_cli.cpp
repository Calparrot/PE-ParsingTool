#include <filesystem>
#include <string>
#include <iostream>

#include "api.h"

namespace fs = std::filesystem;

#ifdef _WIN32
#include <Windows.h>
std::string wstring_to_string(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(
        CP_UTF8, 0, wstr.c_str(), (int)wstr.length(), NULL, 0, NULL, NULL
    );
    std::string utf8_str(size_needed, 0);
    WideCharToMultiByte(
        CP_UTF8, 0, wstr.c_str(), (int)wstr.length(), &utf8_str[0], size_needed, NULL, NULL
    );
    return utf8_str;
}
#else
#include <clocale>
#include <cstdlib>

static bool locale_initialized = []() {
    std::setlocale(LC_ALL, "");
    return true;
    }();

std::string wstring_to_string(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();

    std::setlocale(LC_ALL, "");

    size_t size_needed = wcstombs(nullptr, wstr.c_str(), 0);
    if (size_needed == (size_t)-1) { // 转换失败（包含无法转换的字符）
        return std::string(); 
    }

    std::string result(size_needed, '\0');
    size_t converted = wcstombs(&result[0], wstr.c_str(), size_needed);
    if (converted == (size_t)-1) {
        return std::string();
    }

    return result;
}
#endif

int main(int argc, char* argv[]) {
    auto start_time = std::chrono::steady_clock::now(); // 开始计时
	fs::path scan_dir;                                  // 需要扫描的文件夹路径

	if (argc >= 2) {
		scan_dir = argv[1];                             // 使用命令行参数
	}
	else {
		scan_dir = ".";                                 // 默认当前目录
	}

	if (!fs::exists(scan_dir) || !fs::is_directory(scan_dir)) {
		std::cerr << "错误: 目录不存在 - " << scan_dir << std::endl;
		return 1;
	}
	std::cout << "扫描目录: " << fs::absolute(scan_dir) << std::endl;

    ScanResultsDistribution sr_distribution;
	int total_files = 0;                                 // 扫描文件总数计数

    for (const auto& entry : fs::directory_iterator(scan_dir)) {
        FundamentalAnalysis object;
        if (!entry.is_regular_file()) {
            continue;
        }

        std::string ext = entry.path().extension().string();
        
        if (ext == ".exe" || ext == ".dll") {
            std::wstring wpath = entry.path().wstring();
            std::string file_path = wstring_to_string(wpath);

            FundamentalAnalysis::error_code err = object.analysis_file(file_path);
			ScanResultsDistribution current = object.summary_file();

            if (current.effective_structure) {
                total_files++;
            }
			sr_distribution.info_num += current.info_num;
			sr_distribution.suspicious_num += current.suspicious_num;
			sr_distribution.warning_num += current.warning_num;
			sr_distribution.error_num += current.error_num;
			for (int i = 0; i < 20; i++) {
				sr_distribution.info_distribution[i] += current.info_distribution[i];
				sr_distribution.suspicious_distribution[i] += current.suspicious_distribution[i];
				sr_distribution.warning_distribution[i] += current.warning_distribution[i];
				sr_distribution.error_distribution[i] += current.error_distribution[i];
			}
            for (int i = 0; i < 11; i++) {
                sr_distribution.type_distribution[i] += current.type_distribution[i];
            }

            if (current.warning_num != 0) {
                std::wstring output_dir;
                /*std::wstring output_dir = L"E:\\个人文档\\4\\PE_Parsing CLI\\x64\\output";
                fs::create_directories(output_dir);*/

                std::wstring filename = entry.path().stem().wstring();  // 不带扩展名的文件名
                std::wstring report_name = filename + L"_report.txt";

                fs::path report_path = fs::path(output_dir) / report_name;

                std::wstring final_path = report_path.wstring();
                int counter = 1;
                while (fs::exists(final_path)) {
                    std::wstring new_name = filename + L"_report(" + std::to_wstring(counter) + L").txt";
                    final_path = (fs::path(output_dir) / new_name).wstring();
                    counter++;
                }

                if (object.data_manager.scan_report_export(final_path)) {
                    std::wcout << L"报告已导出: " << final_path << std::endl;
                }
                else {
                    std::wcout << L"导出失败: " << filename << std::endl;
                }
            }
        }
    }

	std::cout << "\n=================================================\n";
	std::cout << "扫描完成：共分析 " << total_files << " 个文件\n";

    // 基础统计
    std::cout << "【基础统计】\n";
    std::cout << "信息数量: " << sr_distribution.info_num << std::endl;
    std::cout << "可疑数量: " << sr_distribution.suspicious_num << std::endl;
    std::cout << "警告数量: " << sr_distribution.warning_num << std::endl;
    std::cout << "错误数量: " << sr_distribution.error_num << std::endl;
    std::cout << std::endl;

    // 分布统计（只显示非零的）
    std::cout << "【详细分布】\n";

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

    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    //输出耗时
    std::cout << "\n=================================================\n";
    std::cout << "总耗时: " << duration.count() << " ms";
    if (duration.count() >= 1000) {
        std::cout << " (" << (duration.count() / 1000.0) << " 秒)";
    }
    std::cout << std::endl;

	return 0;
}