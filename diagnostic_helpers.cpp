#include <sstream>
#include <string>

#include "diagnostic_codes.h"

/* 懒人模板 */
// 创建字段相关的诊断，重载VALUE_MISMATCH
// 【{severity}】{description} -> {field_name}字段异常，期望/阈值/参考值：{expected}，实际值：{actual}
Core::Diagnostic value_mismatch(
	Core::Severity severity,
    const std::string& field,
    const std::string& description,
    uint32_t expected,
    uint32_t actual,
    uint64_t offset
) {
    Core::Diagnostic d;
    d.object = Core::Object::FIELD;
    d.severity = severity;
    d.category = Core::DiagCategory::VALUE_MISMATCH;
    d.field_name = field;
    d.description = description;
	d.expected_value = expected;
    d.actual_value = actual;
    d.offset = offset;
    return d;
}

// 创建字段相关的诊断，重载INVALID_VALUE
// 【{severity}】{description} -> {field_name}字段值无效，实际值：{actual}
Core::Diagnostic invalid_value(
    Core::Severity severity,
    const std::string& field,
        const std::string& description,
        uint32_t actual,
        uint64_t offset,
		bool is_signature
) {
    Core::Diagnostic d;
    d.object = is_signature ? Core::Object::SIGNATURE : Core::Object::FIELD;
    d.severity = severity;
    d.category = Core::DiagCategory::VALUE_MISMATCH;
    d.field_name = field;
    d.description = description;
    d.actual_value = actual;
    d.offset = offset;
    return d;
}

// 创建地址相关的诊断
// 【{severity}】{description} -> {field_name}所示地址异常，值：0x{address}
Core::Diagnostic excursion_anomaly(
    Core::Severity severity,
    const std::string& field,
    const std::string& description,
    uint64_t address
) {
    Core::Diagnostic d;
    d.object = Core::Object::ADDRESS_IN_FIELD;
    d.severity = severity;
    d.category = Core::DiagCategory::EXCURSION_ANOMALY;
    d.field_name = field;
    d.description = description;
	d.address = address;
    return d;
}
    
// 创建地址相关的诊断
// 【{severity}】{description} -> {field_name}地址超过文件/内存范围，值：0x{address}
Core::Diagnostic address_out_of_range(
    Core::Severity severity,
    const std::string& field,
    const std::string& description,
    uint64_t address
) {
    Core::Diagnostic d;
    d.object = Core::Object::ADDRESS_IN_FIELD;
    d.severity = severity;
    d.category = Core::DiagCategory::ADDRESS_OUT_OF_RANGE;
    d.field_name = field;
    d.description = description;
    d.address = address;
    return d;
}

// 创建结构相关的诊断
// 【{severity}】{description}长度异常，实际长度：{actual}字节
Core::Diagnostic abnormal_length(
    Core::Severity severity,
    const std::string& description,
    uint32_t actual,
    uint64_t offset
) {
    Core::Diagnostic d;
    d.object = Core::Object::STRUCTURE;
    d.severity = severity;
    d.category = Core::DiagCategory::ABNORMAL_LENGTH;
    d.description = description;
    d.actual_value = actual;
    d.offset = offset;
    return d;
}

// 创建结构相关的诊断
// 【{severity}】{description}区域缺失
Core::Diagnostic structure_missing(
    Core::Severity severity,
    const std::string& description
) {
    Core::Diagnostic d;
    d.object = Core::Object::STRUCTURE;
    d.severity = severity;
    d.category = Core::DiagCategory::STRUCTURE_MISSING;
    d.description = description;
    return d;
}

// 创建字段信息相关的诊断
// 【{severity}】{description} -> {field_name}：{info1}
Core::Diagnostic detailed_information(
    Core::Severity severity,
    const std::string& field,
    const std::string& description,
    const std::string& info1,
    uint64_t offset
) {
    Core::Diagnostic d;
    d.object = Core::Object::IMFORMATION_IN_FIELD;
    d.severity = severity;
    d.category = Core::DiagCategory::DETAILED_INFORMATION;
    d.field_name = field;
    d.description = description;
	d.info1 = info1;
    d.offset = offset;
    return d;
}

// 创建结构地址相关的诊断
// 【{severity}】{description}{info1}
Core::Diagnostic regular_issue(
    Core::Severity severity,
    const std::string& description,
    const std::string& info1,
    uint64_t offset
) {
    Core::Diagnostic d;
    d.object = Core::Object::STRUCTURE_ADDRESS;
    d.severity = severity;
    d.category = Core::DiagCategory::REGULAR_ISSUE;
    d.description = description;
    d.info1 = info1;
    d.offset = offset;
    return d;
}

// 创建结构地址相关的诊断
// 【{severity}】{description}[{index}]{info1}
Core::Diagnostic indexed_issue(
    Core::Severity severity,
    const std::string& description,
    size_t index,
    const std::string& info1,
    uint64_t offset
) {
    Core::Diagnostic d;
    d.object = Core::Object::STRUCTURE_ADDRESS;
    d.severity = severity;
    d.category = Core::DiagCategory::INDEXED_ISSUE;
    d.description = description;
    d.index = index;
    d.info1 = info1;
    d.offset = offset;
    return d;
}

// 创建关系相关的诊断
// 【{severity}】{description} -> {field_name}与{compared_description} -> {compared_field_name}：{info1}
Core::Diagnostic relationship_issue(
    Core::Severity severity,
    const std::string& field,
    const std::string& description,
    const std::string& compared_field,
    const std::string& compared_description,
    const std::string& info1,
    uint64_t offset
) {
    Core::Diagnostic d;
    d.object = Core::Object::FIELD;
    d.severity = severity;
    d.category = Core::DiagCategory::RELATIONSHIP_ISSUE;
    d.field_name = field;
    d.description = description;
    d.compared_field_name = compared_field;
    d.compared_description = compared_description;
    d.info1 = info1;
    d.offset = offset;
    return d;
}

// 创建额外信息相关的诊断
// {info2}
Core::Diagnostic additional_information(
    const std::string& info2,
    uint64_t offset
) {
    Core::Diagnostic d;
    d.object = Core::Object::STRUCTURE;
    d.severity = Core::Severity::INFO_LOW;
    d.category = Core::DiagCategory::ADDITIONAL_INFORMATION;
    d.info2 = info2;
    d.offset = offset;
    return d;
}