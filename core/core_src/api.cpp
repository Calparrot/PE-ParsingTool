#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>

#include "api.h"

#ifdef _WIN32
#include <windows.h>
std::wstring utf8_to_wide(const std::string& utf8_str) {
    if (utf8_str.empty()) return std::wstring();

    int len = MultiByteToWideChar(CP_UTF8, 0, utf8_str.c_str(), -1, NULL, 0);
    if (len <= 0) return std::wstring();

    std::wstring wide_str(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8_str.c_str(), -1, &wide_str[0], len);
    wide_str.pop_back();
    return wide_str;
}
#endif

/* Translator类 */
/* private */
// 类型转换
std::string Translator::vector_to_hexstring(const std::vector<uint8_t>& input_data) {
    std::stringstream ss;
    ss << std::hex << std::uppercase;
    for (uint8_t byte : input_data) {
        ss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(byte);
    }
    return ss.str();
}
std::string Translator::hexstring_to_ascii(const std::string& hexstring) {
    std::string ascii;

    for (size_t i = 0; i < hexstring.length(); i += 2) {
        if (i + 1 >= hexstring.length()) break;

        std::string byteStr = hexstring.substr(i, 2);
        char* endPtr;
        int byte_val = std::strtol(byteStr.c_str(), &endPtr, 16);

        if (byte_val >= 32 && byte_val <= 126) {
            ascii += static_cast<char>(byte_val);
        }
        else {
            ascii += '.';
        }
    }

    return ascii;
}
std::string Translator::generate_file_display(const std::vector<uint8_t>& input_data, unsigned int basic_address) {
    std::string hexadecimal_view;
    std::string raw_data;
    std::string ascii;
    std::stringstream ss;
    unsigned int temporary_address = 0;
    size_t j = 0;

    raw_data.append(vector_to_hexstring(input_data));
    size_t num = raw_data.length();

    ascii = hexstring_to_ascii(raw_data);

    for (size_t i = 0; i < num; i++) {
        if (i % 32 == 0) {
            ss.str("");
            ss.clear();
            ss << std::hex << std::uppercase;
            ss << std::hex << std::setw(8) << std::setfill('0') << (basic_address + temporary_address);
            hexadecimal_view.append(ss.str());
            hexadecimal_view.append("    ");
            temporary_address += 16;
        }

        hexadecimal_view += (raw_data[i]);
        if ((i + 1) % 2 == 0) {
            hexadecimal_view += " ";
        }
        if (i % 32 == 31) {
            hexadecimal_view += "   ";
            hexadecimal_view.append(ascii, (i + 1) / 2 - 16, 16);
            hexadecimal_view += "\r\n";
        }
    }

    if ((num - 1) % 32 != 31) {
        size_t temp = 31 - ((num - 1) % 32);
        temp += (temp / 2 + 3);
        hexadecimal_view.append(temp, ' ');
    }

    return hexadecimal_view;
}

// 单块翻译
std::string Translator::single_item_degree_translator(Core::Severity severity) {
    std::string degree;
    switch (severity) {
    case Core::Severity::INFO_LOW:
        degree = "【信息】";
        break;
    case Core::Severity::SUSPICIOUS:
        degree = "【可疑】";
        break;
    case Core::Severity::WARNING_MED:
        degree = "【警告】";
        break;
    case Core::Severity::ERROR_HIGH:
        degree = "【错误】";
        break;
    default:
        degree = "【未知】";
        break;
    }

    return degree;
}
std::string Translator::single_item_translator(Core::Diagnostic single_item) {
    std::string individual_result;

    switch (single_item.category) {
    case Core::DiagCategory::ABNORMAL_LENGTH: {
        individual_result += single_item_degree_translator(single_item.severity);
        individual_result += single_item.description;
        individual_result += "长度异常，实际长度：";
        individual_result += uint_to_hex_string(single_item.actual_value);
        individual_result += "字节";
        break;
    }
    case Core::DiagCategory::ADDITIONAL_INFORMATION: {
        individual_result += single_item.info2;
        break;
    }
    case Core::DiagCategory::ADDRESS_OUT_OF_RANGE: {
        individual_result += single_item_degree_translator(single_item.severity);
        individual_result += single_item.description;
        individual_result += " -> ";
        individual_result += single_item.field_name;
        individual_result += "地址超过文件/内存范围，值：";
        individual_result += uint_to_hex_string(single_item.address);
        break;
    }
    case Core::DiagCategory::DETAILED_INFORMATION: {
        individual_result += single_item_degree_translator(single_item.severity);
        individual_result += single_item.description;
        individual_result += " -> ";
        individual_result += single_item.field_name;
        individual_result += "：";
        individual_result += single_item.info1;
        break;
    }
    case Core::DiagCategory::EXCURSION_ANOMALY: {
        individual_result += single_item_degree_translator(single_item.severity);
        individual_result += single_item.description;
        individual_result += " -> ";
        individual_result += single_item.field_name;
        individual_result += "所示地址异常，值：";
        individual_result += uint_to_hex_string(single_item.address);
        break;
    }
    case Core::DiagCategory::INDEXED_ISSUE: {
        individual_result += single_item_degree_translator(single_item.severity);
        individual_result += single_item.description;
        individual_result += "[";
        individual_result += uint_to_dec_string(single_item.index);
        individual_result += "]";
        individual_result += single_item.info1;
        break;
    }
    case Core::DiagCategory::INVALID_VALUE: {
        individual_result += single_item_degree_translator(single_item.severity);
        individual_result += single_item.description;
        individual_result += " -> ";
        individual_result += single_item.field_name;
        individual_result += "字段值无效，实际值：";
        individual_result += uint_to_hex_string(single_item.actual_value);
        break;
    }
    case Core::DiagCategory::REGULAR_ISSUE: {
        individual_result += single_item_degree_translator(single_item.severity);
        individual_result += single_item.description;
        individual_result += single_item.info1;
        break;
    }
    case Core::DiagCategory::RELATIONSHIP_ISSUE: {
        individual_result += single_item_degree_translator(single_item.severity);
        individual_result += single_item.description;
        individual_result += " -> ";
        individual_result += single_item.field_name;
        individual_result += "与";
        individual_result += single_item.compared_description;
        individual_result += " -> ";
        individual_result += single_item.compared_field_name;
        individual_result += "：";
        individual_result += single_item.info1;
        break;
    }
    case Core::DiagCategory::STRUCTURE_MISSING: {
        individual_result += single_item_degree_translator(single_item.severity);
        individual_result += single_item.description;
        individual_result += "区域缺失";
        break;
    }
    case Core::DiagCategory::VALUE_MISMATCH: {
        individual_result += single_item_degree_translator(single_item.severity);
        individual_result += single_item.description;
        individual_result += " -> ";
        individual_result += single_item.field_name;
        individual_result += "字段异常，期望/阈值/参考值：";
        individual_result += uint_to_hex_string(single_item.expected_value);
        individual_result += "，实际值：";
        individual_result += uint_to_hex_string(single_item.actual_value);
    }
    }

    return individual_result;
}

std::string Translator::get_sct_address_table() {
    std::string table;
    table += "\n【节区文件地址表】\n";
    table += "——\t——\t——\t——\t——\t——\t——\t——\t——\n";
    table += "序号\t|起始偏移\t|结束偏移\t|数据长度\t|对齐长度\n";
    table += "——\t——\t——\t——\t——\t——\t——\t——\t——\n";
    for (size_t i = 0; i < data_container.storage_interval_table.size(); i++) {
        table += std::to_string(i + 1) + "\t|";
        table += uint_to_hex_string(data_container.storage_interval_table[i].begin) + "\t|";
        table += uint_to_hex_string(data_container.storage_interval_table[i].end) + "\t|";
        table += uint_to_hex_string(data_container.storage_interval_table[i].size) + "\t|";
        table += uint_to_hex_string(data_container.storage_interval_table[i].alignment_length);
        table += "\n";
    }
    table += "注：结束偏移含对齐\n";

    table += "\n【节区内存地址表】\n";
    table += "——\t——\t——\t——\t——\t——\t——\t——\t——\n";
    table += "序号\t|起始偏移\t|结束偏移\t|数据长度\t|对齐长度\n";
    table += "——\t——\t——\t——\t——\t——\t——\t——\t——\n";
    for (size_t i = 0; i < data_container.memory_interval_table.size(); i++) {
        table += std::to_string(i + 1) + "\t|";
        table += uint_to_hex_string(data_container.memory_interval_table[i].begin) + "\t|";
        table += uint_to_hex_string(data_container.memory_interval_table[i].end) + "\t|";
        table += uint_to_hex_string(data_container.memory_interval_table[i].size) + "\t|";
        table += uint_to_hex_string(data_container.memory_interval_table[i].alignment_length);
        table += "\n";
    }
    table += "注：结束偏移含对齐\n";

    return table;
}

// 整合翻译
std::string Translator::basic_file_info_translator() {
    std::string basic_info;
    basic_info += "【基础扫描信息】\n\n";
    basic_info += ("模式：" + data_container.comprehensive_info_.file_identification_ + "\n"); // 32位或64位
    basic_info += ("架构：" + data_container.comprehensive_info_.architecture_ + "\n");
    basic_info += ("文件大小：" + uint_to_dec_string(data_container.comprehensive_info_.file_size_copy_) + "字节\n");

    return basic_info;
}
std::string Translator::aggregate_info_translator(){
    std::string agrt_info;

    agrt_info += get_sct_address_table();

    return agrt_info;
}
std::string Translator::detailed_file_info_translator() {
    std::string detailed_info;

    detailed_info += "\n【详细信息】\n";
    if (data_container.num_of_scanned_blocks_ >= 1) {
        for (size_t i = 0; (i < data_container.diarelist.size()) && (i < data_container.num_of_scanned_blocks_); i++) {
            for (size_t j = 0; j < data_container.diarelist[i].information_list_.size(); j++) {
                detailed_info += single_item_translator(data_container.diarelist[i].information_list_[j]);
                detailed_info += "\n";
            }
        }
    }
    else {
        detailed_info += " ！ 扫描出错了，无法获取输出范围。";
    }
    

    return detailed_info;
}

// 写文件
bool Translator::string_to_file_append(const std::wstring& export_filepath, const std::string& input_data) {
    std::ofstream output_file(export_filepath, std::ios::app | std::ios::binary); // 追加写入而不是覆盖
    if (!output_file.is_open()) {
        return false;
    }

    output_file << input_data;
    output_file.close();
    return true;
}

/* public */
bool Translator::hexadecimal_document_export(const std::wstring& export_filepath) {
	unsigned int file_size = data_container.source_file_data.size();
	unsigned int offset = 0;
	unsigned int chunk_size = 1024; 
    std::vector<uint8_t> current_data;

    while (offset < file_size) {
        unsigned int current_size = (chunk_size <= file_size - offset) ? chunk_size : file_size - offset;
        current_data.assign(
            data_container.source_file_data.begin() + offset,
            data_container.source_file_data.begin() + offset + current_size
        );

        if (!string_to_file_append(export_filepath, generate_file_display(current_data, offset))) {
            return false;
        }

        offset += chunk_size;
    }
    return true;
}

bool Translator::scan_report_export(const std::wstring& export_filepath) {
    if (!string_to_file_append(export_filepath, basic_file_info_translator()) ||
    !string_to_file_append(export_filepath, aggregate_info_translator()) ||
    !string_to_file_append(export_filepath, detailed_file_info_translator())) {
        return false;
    }

    return true;
}

/* FundamentalAnalysis类 */
bool FundamentalAnalysis::readfile(std::string file_path) {
#ifdef _WIN32 // Windows平台：使用宽字符版本
    std::wstring wpath = utf8_to_wide(file_path);
    myfile.open(wpath.c_str(), std::ios::binary);
#else         // Linux/Mac平台：直接使用UTF-8路径
    myfile.open(file_path.c_str(), std::ios::binary);
#endif
    if (!myfile.is_open()) {
        return false;
    }
    myfile.seekg(0, std::ios::end);
    file_size = myfile.tellg();
    myfile.seekg(0, std::ios::beg);
    myfile_loaded = true;

    /* 临时方案 */
    data_manager.data_container.source_file_data.resize(2048);
    myfile.read(reinterpret_cast<char*>(data_manager.data_container.source_file_data.data()), 2048);

    return true;
}

bool FundamentalAnalysis::check_little_endian() {
    uint32_t test = 0x12345678;
    if (*(uint8_t*)&test != 0x78) {
		return false; // 非小端序
    }
	return true;      // 小端序
}

FundamentalAnalysis::error_code FundamentalAnalysis::analysis_file(const std::string input_filepath) {
    if (!check_little_endian()) {
        return error_code::PLATFORM_NOT_SUPPORTED;
	}

    bool previous_execution_result = readfile(input_filepath);
    uint8_t execution_steps = 0; // 记录执行到多少个步骤，不管成功还是失败
    PEanalyzer target(myfile);

    if (previous_execution_result) {
        // 初始化工作
        // data_manager.data_container.sr_file_size_ = target.file_size_;
        data_manager.data_container.comprehensive_info_.file_size_copy_ = target.file_size_;
    }
    if (previous_execution_result) {
        previous_execution_result = target.dosheader_analysis(data_manager.data_container);
        execution_steps++;
    }
    if (previous_execution_result) {
        previous_execution_result = target.dosstub_analysis(data_manager.data_container);
        execution_steps++;
    }
    if (previous_execution_result) {
        previous_execution_result = target.file_header_analysis(data_manager.data_container);
        execution_steps++;
    }
    if (previous_execution_result) {
        previous_execution_result = target.optional_header_analysis(data_manager.data_container);
        execution_steps++;
    }
    if (previous_execution_result) {
        previous_execution_result = target.section_headers_analysis(data_manager.data_container);
        execution_steps++;
    }
    if (previous_execution_result) {
        previous_execution_result = target.import_descriptor_seeker(data_manager.data_container);
        execution_steps++;
    }

    if (previous_execution_result) {
        /* 在这调文件置信度检测函数 */
        return error_code::SUCCESS;
    }
    else {
        std::ifstream test(input_filepath);
        switch (execution_steps) {
        case 0:
            if (!test.good()) {
                return error_code::FILE_NOT_FOUND;
            }
            test.close();
            return error_code::FILE_ACCESS_DENIED;
        default:
            data_manager.data_container.num_of_scanned_blocks_ = execution_steps;
            /* 在这调文件置信度检测函数 */
            return error_code::SUCCESS;
        }
    }
}

ScanResultsDistribution FundamentalAnalysis::summary_file() {
    ScanResultsDistribution results_distrubution;

    if (myfile_loaded == true) {
        for (int i = 0; i < data_manager.data_container.diarelist.size(); i++) {
            for (int j = 0; j < data_manager.data_container.diarelist[i].information_list_.size(); j++) {
                switch (data_manager.data_container.diarelist[i].information_list_[j].severity) {
                case Core::Severity::ERROR_HIGH:
                    results_distrubution.error_distribution[i]++;
                    results_distrubution.error_num++;
                    break;
                case Core::Severity::WARNING_MED:
                    results_distrubution.error_distribution[i]++;
                    results_distrubution.error_num++;
                    break;
                case Core::Severity::SUSPICIOUS:
                    results_distrubution.suspicious_distribution[i]++;
                    results_distrubution.suspicious_num++;
                    break;
                case Core::Severity::INFO_LOW:
                    results_distrubution.info_distribution[i]++;
                    results_distrubution.info_num++;
                    break;
                }

                switch (data_manager.data_container.diarelist[i].information_list_[j].category) {
                case Core::DiagCategory::VALUE_MISMATCH:
                    results_distrubution.type_distribution[0]++;
                    break;
                case Core::DiagCategory::INVALID_VALUE:
                    results_distrubution.type_distribution[1]++;
                    break;
                case Core::DiagCategory::EXCURSION_ANOMALY:
                    results_distrubution.type_distribution[2]++;
                    break;
                case Core::DiagCategory::ADDRESS_OUT_OF_RANGE:
                    results_distrubution.type_distribution[3]++;
                    break;
                case Core::DiagCategory::ABNORMAL_LENGTH:
                    results_distrubution.type_distribution[4]++;
                    break;
                case Core::DiagCategory::STRUCTURE_MISSING:
                    results_distrubution.type_distribution[5]++;
                    break;
                case Core::DiagCategory::DETAILED_INFORMATION:
                    results_distrubution.type_distribution[6]++;
                    break;
                case Core::DiagCategory::REGULAR_ISSUE:
                    results_distrubution.type_distribution[7]++;
                    break;
                case Core::DiagCategory::INDEXED_ISSUE:
                    results_distrubution.type_distribution[8]++;
                    break;
                case Core::DiagCategory::RELATIONSHIP_ISSUE:
                    results_distrubution.type_distribution[9]++;
                    break;
                case Core::DiagCategory::ADDITIONAL_INFORMATION:
                    results_distrubution.type_distribution[10]++;
                    break;
                }
            }
        }
    }
    else {
        results_distrubution.effective_structure = false;
        return results_distrubution;
    }

    return results_distrubution;
}