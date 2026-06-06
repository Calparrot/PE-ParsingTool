#include <filesystem>
#include <string>
#include <iostream>

#include "api.h"
#include "functions.h"

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
        (char*)"-e",
        (char*)"single",
        (char*)"C:\\test\\Helloworldx32.exe"
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
	if (cmd == "-h" || cmd == "--help" || cmd == "help") {               // 显示帮助文档
        show_help();
        return 0;
    }
    if (cmd == "-v" || cmd == "--version" || cmd == "version"){          // 显示版本信息
        std::cout << "PE_Parsing CLI 版本 0.0.0\n";
        std::cout << "其实都没有正式版本，功能还在开发中。\n" << std::endl;
        return 0;
	}
    if (cmd == "-s" || cmd == "--scan" || cmd == "scan") {               // 扫描指定目录
        if (argc < 4) {
            std::cerr << "错误：扫描需要子命令和路径\n" << std::endl;
            return 1;
        }

        std::string sub = argv[2];               // file 或 folder
#ifdef _WIN32
		fs::path scan_dir = AnsiToUtf8(argv[3]); // 需要扫描的文件或文件夹路径，有点问题，不要传中文路径
#else
        fs::path scan_dir = argv[3];             // 需要扫描的文件或文件夹路径
#endif
        if (sub != "file" && sub != "folder") {
            std::cerr << "错误：子命令不存在" << sub << std::endl;
            return 1;
        }
        if (!fs::exists(scan_dir) && !fs::is_directory(scan_dir)) {
            std::cerr << "错误：路径不存在 - " << scan_dir << std::endl;
            return 1;
        }
        /* scan子命令 */
        if(sub == "folder") {                                          // 扫描指定目录文件夹模式
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
                }
            }

            batch_statistiacl_output(sr_distribution, total_files);
	    }
		else if (sub == "file") {                                        // 扫描指定文件模式
            std::cout << "扫描文件：" << fs::absolute(scan_dir) << std::endl;
            FundamentalAnalysis object;
			std::string file_path = wstring_to_string(scan_dir.wstring());
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
    if (cmd == "-e" || cmd == "--export" || cmd == "export") {             // 导出扫描报告
		std::cout << "因路径处理问题，本功能暂不可用。" << std::endl;
        return 0;

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
#ifdef _WIN32
        fs::path scan_dir = AnsiToUtf8(argv[3]); // 需要扫描的文件或文件夹路径，有点问题，不要传中文路径
		fs::path out_dir;                        // 输出文件路径
        if(argc == 6) {
            out_dir = AnsiToUtf8(argv[5]);
		}
#else
        fs::path scan_dir = argv[3];             // 需要扫描的文件或文件夹路径
        fs::path out_dir;                        // 输出文件路径
        if (argc == 6) {
            out_dir = argv[5];
        }
#endif
        if (sub != "single" && sub != "folder") {
            std::cerr << "错误：子命令不存在 - " << sub << std::endl;
            return 1;
        }
        if (!fs::exists(scan_dir) && !fs::is_directory(scan_dir)) {
            std::cerr << "错误：需要扫描的文件路径不存在 - " << scan_dir << std::endl;
            return 1;
        }
        if (argc == 6) {
            if (!fs::exists(out_dir) && !fs::is_directory(out_dir)) {
            std::cerr << "错误：指定的导出路径不存在 - " << out_dir << std::endl;
            return 1;
            }
        }
        
        if (sub == "folder") {                                          // 扫描指定目录文件夹模式
            std::cout << "扫描目录：" << fs::absolute(scan_dir) << std::endl;
            int total_files = 0;  // 扫描文件总数计数

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

                    if (current.warning_num != 0) {
                        fs::path tool_dir = fs::absolute(argv[0]).parent_path();
                        std::string output_dir;
                        if (argc == 6) {
                            output_dir = wstring_to_string(out_dir.wstring());
                        }
                        else {
                            output_dir = wstring_to_string(tool_dir.wstring());
						}
                        fs::create_directories(output_dir);

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
        }
        else if(sub == "single") {                                      // 扫描指定文件模式
            std::cout << "扫描目录：" << fs::absolute(scan_dir) << std::endl;
            FundamentalAnalysis object;
            std::string file_path = wstring_to_string(scan_dir.wstring());
            FundamentalAnalysis::error_code err = object.analysis_file(file_path);
            if (err == FundamentalAnalysis::error_code::SUCCESS) {
                fs::path tool_dir = fs::absolute(argv[0]).parent_path();
                std::wstring output_dir;
                if (argc == 6) {
                    output_dir = out_dir.wstring() + L"\\" + L"output.txt";
                }
                else {
                    output_dir = tool_dir.wstring() + L"\\" + L"output.txt";
                }
                fs::create_directories(output_dir);
                if (object.data_manager.scan_report_export(output_dir)) {
					std::cout << "报告已导出: " << wstring_to_string(output_dir) << std::endl;
                }
                else {
					std::cout << "导出失败: " << wstring_to_string(output_dir) << std::endl;
                }
            }
            else {
                std::cerr << "错误：分析失败" << file_path << std::endl;
                return 1;
            }
		}
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