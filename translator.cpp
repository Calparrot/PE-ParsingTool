#ifndef UNICODE
#define UNICODE
#endif 

#include <windows.h>
#include <sstream>
#include <iomanip>
#include <string>

#include "database.h"
#include "translator.h"

/* 工具函数 */
std::wstring vector_to_hexstring(const std::vector<uint8_t>& data) {
    std::wstringstream wss;
    for (uint8_t byte : data) {
        wss << std::hex << std::setw(2) << std::setfill(L'0')
            << static_cast<int>(byte);
    }
    return wss.str();
}

std::wstring hexstring_to_ascii(const std::wstring& hexstring) {
    std::wstring ascii;

    for (size_t i = 0; i < hexstring.length(); i += 2) {
        if (i + 1 >= hexstring.length()) break;

        std::wstring byteStr = hexstring.substr(i, 2);
        wchar_t* endPtr;
        int byteValue = std::wcstol(byteStr.c_str(), &endPtr, 16);

        if (byteValue >= 32 && byteValue <= 126) {
            ascii += static_cast<wchar_t>(byteValue);
        }
        else {
            ascii += L'.';
        }
    }

    return ascii;
}

std::wstring degree_judgement(Core::Severity severity) {
	std::wstring degree;
    switch (severity) {
    case Core::Severity::INFO_LOW:
        degree = L"【信息】";
        break;
    case Core::Severity::SUSPICIOUS:
        degree = L"【可疑】";
        break;
    case Core::Severity::WARNING_MED:
        degree = L"【警告】";
        break;
    case Core::Severity::ERROR_HIGH:
        degree = L"【错误】";
        break;
    default:
        degree = L"【未知】";
        break;
	}

	return degree;
}

std::wstring string_to_wstring(const std::string& str, UINT code_page) {
    if (str.empty()) return std::wstring();

    int size_needed = MultiByteToWideChar(
        code_page, 0, str.c_str(), (int)str.size(), NULL, 0
    );

    if (size_needed <= 0) return std::wstring();
    std::wstring wstr(size_needed, L'\0');
    MultiByteToWideChar(
        code_page, 0, str.c_str(), (int)str.size(), &wstr[0], size_needed
    );

    return wstr;
}

/* 翻译函数 */
std::wstring generate_file_display(structuresults data_container) {
	std::wstring source_file_information;
    std::wstring raw_data;
    std::wstring ascii;
    std::wstringstream wss;
    int temporary_address = 0;
    size_t j = 0;

    raw_data.append(struct_to_hexstring(data_container.dosheader));
    if (data_container.structures_attributes.dos_stub_exist_ == true) {
        raw_data += (vector_to_hexstring(data_container.dosstub));
    }
    raw_data.append(struct_to_hexstring(data_container.fileheader));
    if (data_container.file_identification == 32) {
        raw_data += (struct_to_hexstring(data_container.optionalheader32));
    }
    else if (data_container.file_identification == 64) {
        raw_data.append(struct_to_hexstring(data_container.optionalheader64));
    }
    else {
        raw_data.append(struct_to_hexstring(data_container.optionalheaderrom));
    }
    ascii = hexstring_to_ascii(raw_data);

    size_t num = raw_data.length();
	source_file_information.assign(
        L"RVA         00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F    ASCCI\n\n"
    );
    for (size_t i = 0; i < num; i++) {
        if (i % 32 == 0) {
            wss.str(L"");
            wss.clear();
            wss << std::hex << std::setw(8) << std::setfill(L'0') << temporary_address;
            source_file_information.append(wss.str());
            source_file_information.append(L"    ");
            temporary_address += 16;
        }
        
        source_file_information += (raw_data[i]);
        if ((i + 1) % 2 == 0) {
            source_file_information += L" ";
        }
        if (i % 32 == 31) {
            source_file_information += L"   ";
            source_file_information.append(ascii, (i+1)/2 - 16, 16);
            source_file_information += L"\n";
        }
    }
    if ((num - 1) % 32 != 31) {
        size_t temp = 31 - ((num - 1) % 32);
        temp += (temp / 2 + 3) ;
        source_file_information.append(temp, L' ');
    }
    
	return source_file_information;
}

std::wstring result_translator(Core::Diagnostic structured_results) {
    std::wstring individual_result;

    switch (structured_results.category) {
    case Core::DiagCategory::ABNORMAL_LENGTH: {
		individual_result += degree_judgement(structured_results.severity);
		individual_result += string_to_wstring(structured_results.description);
		individual_result += L"长度异常，实际长度：";
        individual_result += std::to_wstring(structured_results.actual_value);
		individual_result += L"字节";
        break;
    }
    case Core::DiagCategory::ADDITIONAL_INFORMATION: {
		individual_result += string_to_wstring(structured_results.info2);
        break;
    }
    case Core::DiagCategory::ADDRESS_OUT_OF_RANGE: {
		individual_result += degree_judgement(structured_results.severity);
		individual_result += string_to_wstring(structured_results.description);
		individual_result += L" -> ";
		individual_result += string_to_wstring(structured_results.field_name);
		individual_result += L"地址超过文件/内存范围，值：";
		individual_result += uint_to_hex_wstring(structured_results.address);
        /*std::wstringstream wss;
		wss << std::hex << std::setw(16) << std::setfill(L'0') << structured_results.address;
		individual_result += wss.str();*/
        break;
    }
    case Core::DiagCategory::DETAILED_INFORMATION: {
		individual_result += degree_judgement(structured_results.severity);
		individual_result += string_to_wstring(structured_results.description);
		individual_result += L" -> ";
		individual_result += string_to_wstring(structured_results.field_name);
		individual_result += L"：";
		individual_result += string_to_wstring(structured_results.info1);
        break;
    }
    case Core::DiagCategory::EXCURSION_ANOMALY: {
		individual_result += degree_judgement(structured_results.severity);
		individual_result += string_to_wstring(structured_results.description);
		individual_result += L" -> ";
		individual_result += string_to_wstring(structured_results.field_name);
		individual_result += L"所示地址异常，值：0x";
		individual_result += uint_to_hex_wstring(structured_results.address);
        /*std::wstringstream wss;
		wss << std::hex << std::setw(16) << std::setfill(L'0') << structured_results.address;
		individual_result += wss.str();*/
        break;
    }
    case Core::DiagCategory::INDEXED_ISSUE: {
		individual_result += degree_judgement(structured_results.severity);
		individual_result += string_to_wstring(structured_results.description);
		individual_result += L"[";
		individual_result += std::to_wstring(structured_results.index);
		individual_result += L"]";
		individual_result += string_to_wstring(structured_results.info1);
        break;
    }
    case Core::DiagCategory::INVALID_VALUE: {
		individual_result += degree_judgement(structured_results.severity);
		individual_result += string_to_wstring(structured_results.description);
		individual_result += L" -> ";
		individual_result += string_to_wstring(structured_results.field_name);
		individual_result += L"字段值无效，实际值：";
		individual_result += uint_to_hex_wstring(structured_results.actual_value);
        break;
    }
    case Core::DiagCategory::REGULAR_ISSUE: {
		individual_result += degree_judgement(structured_results.severity);
		individual_result += string_to_wstring(structured_results.description);
		individual_result += string_to_wstring(structured_results.info1);
        break;
    }
    case Core::DiagCategory::RELATIONSHIP_ISSUE: {
		individual_result += degree_judgement(structured_results.severity);
		individual_result += string_to_wstring(structured_results.description);
		individual_result += L" -> ";
		individual_result += string_to_wstring(structured_results.field_name);
		individual_result += L"与";
		individual_result += string_to_wstring(structured_results.compared_description);
		individual_result += L" -> ";
		individual_result += string_to_wstring(structured_results.compared_field_name);
		individual_result += L"：";
		individual_result += string_to_wstring(structured_results.info1);
        break;
    }
    case Core::DiagCategory::STRUCTURE_MISSING: {
		individual_result += degree_judgement(structured_results.severity);
		individual_result += string_to_wstring(structured_results.description);
		individual_result += L"区域缺失";
        break;
    }
    case Core::DiagCategory::VALUE_MISMATCH: {
        individual_result += degree_judgement(structured_results.severity);
        individual_result += string_to_wstring(structured_results.description);
        individual_result += L" -> ";
        individual_result += string_to_wstring(structured_results.field_name);
        individual_result += L"字段异常，期望/阈值/参考值：";
        std::wstringstream wss;
        wss << std::hex << std::setw(16) << std::setfill(L'0') << structured_results.expected_value;
        individual_result += wss.str();
        individual_result += L"，实际值：";
        wss << std::hex << std::setw(16) << std::setfill(L'0') << structured_results.actual_value;
        individual_result += wss.str();
    }
    }

    return individual_result;
}
std::wstring scan_summary(structuresults data_container) {
    std::wstring scan_results;

    if (data_container.output_range >= 1) {
        for (size_t i = 0; (i < data_container.diarelist.size()) && (i < data_container.output_range - 1); i++) {
            for(size_t j = 0; j < data_container.diarelist[i].information_list_.size(); j++) {
                scan_results += result_translator(data_container.diarelist[i].information_list_[j]);
                scan_results += L"\n";
			}
        }
    }
    else {
        scan_results += L"无法获取输出范围。";
    }

    return scan_results;
}

std::wstring structure_summary(structuresults data_container, int select) {
    if (select < 1 || select > data_container.output_range) {
		return L"输出范围指定有误，无法读取信息。";
    }

	std::wstring s_sum;

    s_sum += L"【结构基本信息】\n";

    s_sum += L"结构名称\t|";
    s_sum += string_to_wstring(data_container.diarelist[select - 1].component_name_);
    s_sum += L"\n起始偏移\t|";
    s_sum += uint_to_hex_wstring(data_container.diarelist[select - 1].file_offset_);
	s_sum += L"\n数据长度\t|";
    s_sum += std::to_wstring(data_container.diarelist[select - 1].data_size_);
	s_sum += L"字节";

    s_sum += L"\n\n【字段详细信息】\n";

	s_sum += L"字段名称\t|字段值\t|其他信息\n";
    s_sum += L" \t \t|偏移\t|存在异常\t|异常信息\n";
    return s_sum;
}