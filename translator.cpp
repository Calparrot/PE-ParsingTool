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
		individual_result += L"地址超过文件/内存范围，值：0x";
		std::wstringstream wss;
		wss << std::hex << std::setw(16) << std::setfill(L'0') << structured_results.address;
		individual_result += wss.str();
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
		std::wstringstream wss;
		wss << std::hex << std::setw(16) << std::setfill(L'0') << structured_results.address;
		individual_result += wss.str();
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
		std::wstringstream wss;
		wss << std::hex << std::setw(16) << std::setfill(L'0') << structured_results.actual_value;
		individual_result += wss.str();
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
    }

    return individual_result;
}

std::wstring scan_summary(structuresults data_container) {
    std::wstring scan_results;

    if (data_container.output_range >= 1) {
        for (size_t i = 0; (i < data_container.diarelist.size()) && (i < data_container.output_range - 1); ++i) {
            for(size_t j = 0; j < data_container.diarelist[i].information_list_.size(); ++j) {
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