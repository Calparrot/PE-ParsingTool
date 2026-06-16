#pragma once

/* 前置声明 */
class Structuresults;

/*
类说明
	ReInspector：原PEanalyzer类增强版本封装
*/
class ReInspector {
private:
	bool dosheader_recheck(Structuresults& data_container);
	bool dosstub_recheck(Structuresults& data_container);
	bool file_header_recheck(Structuresults& data_container);
	bool optional_header_recheck(Structuresults& data_container);
	bool section_headers_recheck(Structuresults& data_container);

public:

};