#pragma once
#include <vector>

/* 前置声明 */
struct Diaresults;

/*
类说明
	SecondaryRecord：原Structuresults类增强版本
类成员说明
	re_diaresults_ ：单个结构复诊断结果
*/
class SecondaryRecord {
public:
	std::vector<Diaresults> rec_diaresults_{};
};