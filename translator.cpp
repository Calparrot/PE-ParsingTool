#ifndef UNICODE
#define UNICODE
#endif 

#include <windows.h>
#include <sstream>
#include <iomanip>

#include "database.h"
#include "translator.h"

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
	source_file_information.assign(L"RVA         00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F    ASCCI\n\n");
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