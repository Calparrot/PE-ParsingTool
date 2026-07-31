#pragma once
#include <fstream>

/* 前置声明 */
class Structuresults;
class SecondaryRecord;

/*
 * ============================================================================
 *  PE 增强分析模块 - 类型速查
 * ============================================================================
 * 
 *  CLASSES（类）
 *  - ReInspector              PE 增强分析类
 * 
 *  MEMBERS - ReInspector 核心成员
 *  - pedata_ 				   接收的文件流
 * 
 *  FUNCTIONS（函数）
 *  【ReInspector 类成员函数（public）说明】
 *  - check_data_nonempty()    检查传入参数是否非空
 *  - *_recheck()              对应结构的细节版分析
 *  - INT_extract()            提取 IMAGE_IMPORT_DESCRIPTOR 对应的模块
 * 
 * ============================================================================
 */

class ReInspector {
private:
	std::ifstream& pedata_;

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
	bool module_name_extract(SecondaryRecord recheck_container, std::ifstream& pedata, Structuresults& data_container);

	/* 构造函数 */
	ReInspector(std::ifstream& inputfile) : pedata_(inputfile) {

	}
};