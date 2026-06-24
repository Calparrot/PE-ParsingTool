#pragma once
#include <fstream>

/* 前置声明 */
class Structuresults;
class SecondaryRecord;

/*
类说明
	ReInspector：原PEanalyzer类增强版本封装
类成员说明
	check_data_nonempty()：用于确认传入参数非空，即确认已做了基础解析，返回true代表非空
	*_recheck()：对应*结构的细节版分析
	INT_extract()：提取导入表IMAGE_IMPORT_DESCRIPTOR对应的模块的
*/
class ReInspector {
private:
	bool check_data_nonempty(Structuresults& data_container);

public:
	/* 要求基础分析完毕后才可调用，用户不可管理，由API统一封装 */
	// 头部增强分析
	bool dosheader_recheck(Structuresults& data_container);
	bool dosstub_recheck(Structuresults& data_container);
	bool file_header_recheck(Structuresults& data_container);
	bool optional_header_recheck(Structuresults& data_container);
	bool section_headers_recheck(Structuresults& data_container);

	// 导入表增强分析
	bool INT_extract(SecondaryRecord recheck_container, std::ifstream& pedata, Structuresults& data_container);
};