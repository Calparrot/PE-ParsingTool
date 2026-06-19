#include <filesystem>
#include <string>
#include <iostream>

#include "api.h"
#include "functions.h"

namespace fs = std::filesystem;

#ifdef _WIN32
#include <Windows.h>
std::string WideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string utf8(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &utf8[0], len, nullptr, nullptr);
    utf8.pop_back();
    return utf8;
}

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

std::string AnsiToUtf8(const std::string& ansi) {
    int len = MultiByteToWideChar(CP_ACP, 0, ansi.c_str(), -1, NULL, 0);
    std::wstring wide(len, 0);
    MultiByteToWideChar(CP_ACP, 0, ansi.c_str(), -1, wide.data(), len);

    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, NULL, 0, NULL, NULL);
    std::string utf8(utf8_len, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, utf8.data(), utf8_len, NULL, NULL);

    return utf8;
}

std::string get_my_path() {
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    fs::path exe_path = buffer;
    return exe_path.parent_path().string();  // 返回 exe 所在目录
}
#else
#include <clocale>
#include <cstdlib>
#include <unistd.h>
#include <limits.h>

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

std::string get_my_path() {
    char buffer[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (len != -1) {
        buffer[len] = '\0';
        fs::path my_path = buffer;
        return my_path.parent_path().string();
    }
    return "";
}
#endif

int main(int argc, char* argv[]) {
#ifdef _DEBUG
    static char* debug_argv[] = {
        (char*)"PE_ParsingTool_cli.exe",
        (char*)"-s",
        (char*)"folder",
        (char*)"C:\\test"
    };
    argc = 4;
    argv = debug_argv;
#endif

    auto start_time = std::chrono::steady_clock::now(); // 开始计时

    /* 无参数情况下直接显示帮助文档 */
    if (argc < 2) { 
        show_help();
        return 0;
    }

    /* 有参数情况 */
    std::string cmd = argv[1];

	// 显示帮助文档，PE_ParsingTool_cli.exe -h
	if (cmd == "-h" || cmd == "--help" || cmd == "help") {
        show_help();
        return 0;
    }

	// 显示版本信息，PE_ParsingTool_cli.exe -v
    else if (cmd == "-v" || cmd == "--version" || cmd == "version"){
        show_version();
        return 0;
	}

	// 扫描指定目录或文件，PE_ParsingTool_cli.exe -s folder C:\test
    else if (cmd == "-s" || cmd == "--scan" || cmd == "scan") {
        if (argc < 4) {
            std::cerr << "错误：扫描需要子命令和路径\n" << std::endl;
            return 1;
        }

        std::string sub = argv[2];   // file 或 folder
        fs::path scan_dir = argv[3]; // 需要扫描的文件或文件夹路径

        if (sub != "file" && sub != "folder") {
            std::cerr << "错误：子命令不存在" << sub << std::endl;
            return 1;
        }
        /* scan子命令 */
        if(sub == "folder") { // 扫描指定目录文件夹模式
            if(!fs::is_directory(scan_dir)) {
                std::cerr << "错误：需要扫描的文件夹不存在或传入参数非文件夹路径 - " << scan_dir << std::endl;
                return 1;
			}
            std::cout << "扫描目录：" << fs::absolute(scan_dir) << std::endl;

            ScanResultsDistribution sr_distribution;
            int total_files = 0;  // 扫描文件总数计数

            for (const auto& entry : fs::directory_iterator(scan_dir)) {
                FundamentalAnalysis object;
                if (!entry.is_regular_file()) {
                    continue;
                }

                std::string ext = entry.path().extension().string();

                if (ext == ".exe" || ext == ".dll") {
#ifdef _WIN32 // Windows：从宽字符转 UTF-8
                    std::string file_path = WideToUtf8(entry.path().wstring());
#else         // Linux/Mac：直接使用 UTF-8 路径
                    std::string file_path = entry.path().string();
#endif
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
                }
            }

            batch_statistiacl_output(sr_distribution, total_files);
	    }
		else if (sub == "file") { // 扫描指定文件模式
            if (!fs::exists(scan_dir)) {
                std::cerr << "错误：需要扫描的文件不存在或传入参数非文件路径 - " << scan_dir << std::endl;
                return 1;
            }
            std::cout << "扫描文件：" << fs::absolute(scan_dir) << std::endl;

#ifdef _WIN32 // Windows：从宽字符转 UTF-8
            std::string file_path = WideToUtf8(scan_dir.wstring());
#else         // Linux/Mac：直接使用 UTF-8 路径
            std::string file_path = scan_dir.string();
#endif
            FundamentalAnalysis object;
            FundamentalAnalysis::error_code err = object.analysis_file(file_path);

            if(err == FundamentalAnalysis::error_code::SUCCESS) {
				std::cout << "扫描完成，结果如下：" << std::endl;
                object.data_manager.print_report();
			}
            else {
                std::cerr << "错误：分析失败" << file_path << std::endl;
                return 1;
            }
        }
	}

	// 扫描并导出扫描报告，PE_ParsingTool_cli.exe -e folder C:\test -o C:\output
    else if (cmd == "-e" || cmd == "--export" || cmd == "export") {
        if (argc < 4) {
            std::cerr << "错误：扫描需要子命令和路径\n" << std::endl;
            return 1;
        }
        else {
            if(argc != 4 && argc != 6) {
                std::cerr << "错误：导出需要子命令、输入路径和输出路径\n" << std::endl;
                return 1;
			}
        }

        std::string sub = argv[2];               // single 或 folder
        fs::path scan_dir = argv[3];             // 需要扫描的文件或文件夹路径
        fs::path out_dir;                        // 输出文件路径
        if (argc == 6) {
            out_dir = argv[5];
        }

        if (sub != "single" && sub != "folder") {
            std::cerr << "错误：子命令不存在 - " << sub << std::endl;
            return 1;
        }
        
        if (sub == "folder") { // 扫描指定目录文件夹模式
            if (!fs::is_directory(scan_dir)) {
                std::cerr << "错误：需要扫描的文件夹不存在或传入参数非文件夹路径 - " << scan_dir << std::endl;
                return 1;
            }
            if (argc == 6) {
                if (!fs::is_directory(out_dir)) {
                    std::cerr << "错误：指定的导出路径不存在或传入参数非文件夹路径 - " << out_dir << std::endl;
                    return 1;
                }
            }

            std::cout << "扫描目录：" << fs::absolute(scan_dir) << std::endl;
            int total_files = 0;  // 扫描文件总数计数

            for (const auto& entry : fs::directory_iterator(scan_dir)) {
                FundamentalAnalysis object;
                if (!entry.is_regular_file()) {
                    continue;
                }

                std::string ext = entry.path().extension().string(); // 文件后缀

                if (ext == ".exe" || ext == ".dll") {
#ifdef _WIN32 // Windows：从宽字符转 UTF-8
                    std::string file_path = WideToUtf8(entry.path().wstring());
#else         // Linux/Mac：直接使用 UTF-8 路径
                    std::string file_path = entry.path().string();
#endif
                    FundamentalAnalysis::error_code err = object.analysis_file(file_path);
                    ScanResultsDistribution current = object.summary_file();

                    std::string output_dir;
                    if (argc == 6) {
                        output_dir = out_dir.string();
                    }
                    else {
                        fs::path tool_dir = fs::absolute(argv[0]).parent_path();
                        output_dir = tool_dir.string();
                    }
                    // fs::create_directories(output_dir);
                    
                    std::string filename = entry.path().stem().string(); // 不带扩展名的文件名
                    std::string report_name = filename + "_report.txt";  // 带扩展名的文件名
                    fs::path report_path = fs::path(output_dir) / report_name; // 输出文件完整路径
                    std::string final_path = report_path.string(); // 输出文件完整路径的string版本

                    int counter = 1;
                    while (fs::exists(final_path)) {
                        std::string new_name = filename + "_report(" + std::to_string(counter) + ").txt";
                        final_path = (fs::path(output_dir) / new_name).string();
                        counter++;
                    }

                    if (object.data_manager.scan_report_export(final_path)) {
                        std::cout << "报告已导出: " << final_path << std::endl;
                    }
                    else {
                        std::cout << "报告已导出: " << final_path << std::endl;
                    }
                }
            }
        }
        else if(sub == "single") { // 扫描指定文件模式
            if (!fs::exists(scan_dir)) {
                std::cerr << "错误：需要扫描的文件不存在或传入参数非文件路径 - " << scan_dir << std::endl;
                return 1;
            }
            if (argc == 6) {
                if (!fs::exists(out_dir)) {
                    std::cerr << "错误：指定的导出路径不存在或传入参数非文件路径 - " << out_dir << std::endl;
                    return 1;
                }
            }

            std::cout << "扫描目录：" << fs::absolute(scan_dir) << std::endl;

#ifdef _WIN32 // Windows：从宽字符转 UTF-8
            std::string file_path = WideToUtf8(scan_dir.wstring());
#else         // Linux/Mac：直接使用 UTF-8 路径
            std::string file_path = scan_dir.string();
#endif
            FundamentalAnalysis object;
            FundamentalAnalysis::error_code err = object.analysis_file(file_path);

            if (err == FundamentalAnalysis::error_code::SUCCESS) {
                fs::path tool_dir = fs::absolute(argv[0]).parent_path(); // 本程序所在目录

                // std::wstring output_dir;
                std::string output_dir;
                if (argc == 6) {
                    output_dir = out_dir.string() + "/" + "output.txt";
                }
                else {
                    output_dir = tool_dir.string() + "/" + "output.txt";
                }

                if (object.data_manager.scan_report_export(output_dir)) {
                    std::cout << "报告已导出: " << output_dir << std::endl;
                }
                else {
                    std::cout << "导出失败: " << output_dir << std::endl;
                }
            }
            else {
                std::cerr << "错误：分析失败" << file_path << std::endl;
                return 1;
            }
		}
	}

	// 不合法情况，PE_ParsingTool_cli.exe -x
    else {
		std::cout << "参数有误，输入 -h 获取帮助文档。" << std::endl;
    }

    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    std::cout << "\n========================================\n";
    std::cout << "总耗时: " << duration.count() << " ms";
    if (duration.count() >= 1000) {
        std::cout << " (" << (duration.count() / 1000.0) << " 秒)";
    }
    std::cout << std::endl;

	return 0;
}