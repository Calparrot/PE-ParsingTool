#pragma once
#include <vector>
#include <string>

/* 前置声明 */
struct Diaresults;

/* 结构体说明
	RangeItem         ：整数范围项，表示一个整数范围或单个整数，用于导入表地址简化读取，要求T为uint类型
	ImportModuleInfo32：32位 IMAGE_IMPORT_DESCRIPTOR 指向的Name和INT数据
	ImportModuleInfo64：64位 IMAGE_IMPORT_DESCRIPTOR 指向的Name和INT数据
*/
template<typename T>
struct RangeItem {
	T begin;        // 范围起始值（等于实际数据最小值）
	T end;          // 范围结束值（等于实际数据最大值 + pad）
	bool is_range;  // 是否为范围（true表示范围，false表示单点）

	RangeItem(T val) : begin(val), end(val), is_range(false) {}
	RangeItem(T b, T e, bool range) : begin(b), end(e), is_range(range) {}
};

struct ImportModuleInfo32 {
	std::string module_name_;
	std::vector<uint32_t> IMAGE_THUNK_DATA32_;
};

struct ImportModuleInfo64 {
	std::string module_name_;
	std::vector<uint64_t> IMAGE_THUNK_DATA64_;
};

/* 类说明
	SecondaryRecord：原Structuresults类增强版本
类成员说明
	re_diaresults_ ：单个结构复诊断结果
*/
class SecondaryRecord {
public:
	std::vector<Diaresults> rec_diaresults_{};
	
	std::vector<ImportModuleInfo32> in_module_info32_;
	std::vector<ImportModuleInfo32> in_module_info64_;
};