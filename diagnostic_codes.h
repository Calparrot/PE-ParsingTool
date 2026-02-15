#ifndef DIAGNOSTIC_CODES_H
#define DIAGNOSTIC_CODES_H

#include <cstdint>
#include <string>

namespace Core {
    // 分析对象
    enum class Object : uint8_t {
        SIGNATURE,            // 签名
        FIELD,                // 字段本身
        ADDRESS_IN_FIELD,     // 根据字段计算出的地址（适用于简单情况）
        STRUCTURE,            // 结构
        IMFORMATION_IN_FIELD, // 字段所示的信息
		STRUCTURE_ADDRESS     // 结构地址（适用于复杂情况）
    };

    // 严重程度
    enum class Severity : uint8_t {
        INFO_LOW,             // 普通信息
        SUSPICIOUS,           // 可疑
        WARNING_MED,          // 警告
        ERROR_HIGH            // 错误
    };

	// 包含诊断信息
    enum class DiagCategory : uint8_t {
        /* 签名（SIGNATURE）、字段本身（FIELD） */
        VALUE_MISMATCH,        // 【{severity}】{description} -> {field_name}字段异常，期望/阈值/参考值：{expected}，实际值：{actual}
		INVALID_VALUE,		   // 【{severity}】{description} -> {field_name}字段值无效，实际值：{actual}
        
        /* 根据字段计算出的地址（ADDRESS_IN_FIELD） */
        EXCURSION_ANOMALY,     // 【{severity}】{description} -> {field_name}所示地址异常，值：0x{address}
        ADDRESS_OUT_OF_RANGE,  // 【{severity}】{description} -> {field_name}地址超过文件/内存范围，值：0x{address}
        
        /* 结构（STRUCTURE） */
        ABNORMAL_LENGTH,       // 【{severity}】{description}长度异常，实际长度：{actual}字节
        STRUCTURE_MISSING,     // 【{severity}】{description}区域缺失
        
        /* 字段所示的信息（IMFORMATION_IN_FIELD） */
        DETAILED_INFORMATION,  // 【{severity}】{description} -> {field_name}：{info1}
        
        /* 结构地址（STRUCTURE_ADDRESS） */
		REGULAR_ISSUE,         // 【{severity}】{description}{info1}
        INDEXED_ISSUE,         // 【{severity}】{description}[{index}]{info1}
        
        /* 其他问题 */
		RELATIONSHIP_ISSUE,    // 【{severity}】{description} -> {field_name}与{compared_description} -> {compared_field_name}：{info1}
		ADDITIONAL_INFORMATION // {info2}
    };

	// 对象诊断结果所在背景以及包含的诊断信息
    struct Diagnostic {
		Object object;           // 诊断对象
		Severity severity;       // 严重程度
        DiagCategory category;   // 诊断类别（用哪种模板）

        /* 提示信息 */
		std::string info1; // 提示信息1
		std::string info2; // 提示信息2
        /* 基础参数 */
        std::string field_name;  // 字段名，如"PE Signature"
		std::string description; // 结构名，如"File Header"
        uint64_t offset;         // 文件偏移位置
        /* 字段值问题 */
        uint64_t expected_value; // 期望值/阈值/参考值，如"0x00004550"
        uint64_t actual_value;   // 实际值，如"0x12345678"
        /* 地址问题 */
		uint64_t address;        // 地址值，如"0x00400000"
        /* 其他信息 */
        uint64_t index;          // 索引，如节区头索引0、1、2...
		std::string compared_field_name;  // 相关字段名，如"SizeOfHeaders"
		std::string compared_description; // 相关结构名，如"Optional Header"
    };
}

static Core::Diagnostic value_mismatch(
    Core::Severity severity,
    const std::string& field,
    const std::string& description,
    uint32_t expected,
    uint32_t actual,
    uint64_t offset
);
static Core::Diagnostic invalid_value(
    Core::Severity severity,
    const std::string& field,
    const std::string& description,
    uint32_t actual,
    uint64_t offset,
    bool is_signature
);
static Core::Diagnostic excursion_anomaly(
    Core::Severity severity,
    const std::string& field,
    const std::string& description,
    uint64_t address
);
static Core::Diagnostic address_out_of_range(
    Core::Severity severity,
    const std::string& field,
    const std::string& description,
    uint64_t address
);
static Core::Diagnostic abnormal_length(
    Core::Severity severity,
    const std::string& description,
    uint32_t actual,
    uint64_t offset
);
static Core::Diagnostic structure_missing(
    Core::Severity severity,
    const std::string& description
);
static Core::Diagnostic detailed_information(
    Core::Severity severity,
    const std::string& field,
    const std::string& description,
    const std::string& info1,
    uint64_t offset
);
static Core::Diagnostic regular_issue(
    Core::Severity severity,
    const std::string& description,
    const std::string& info1,
    uint64_t offset
);
static Core::Diagnostic indexed_issue(
    Core::Severity severity,
    const std::string& description,
    size_t index,
    const std::string& info1,
    uint64_t offset
);
static Core::Diagnostic relationship_issue(
    Core::Severity severity,
    const std::string& field,
    const std::string& description,
    const std::string& compared_field,
    const std::string& compared_description,
    const std::string& info1,
    uint64_t offset
);
static Core::Diagnostic additional_information(
    const std::string& info2,
    uint64_t offset
);

#endif // !DIAGNOSTIC_CODES_H