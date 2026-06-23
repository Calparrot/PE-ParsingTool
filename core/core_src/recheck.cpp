#include <string>

#include "database.h"
#include "recheck_data.h"

/* private */
bool ReInspector::check_data_nonempty(Structuresults& data_container) {
	if (data_container.structures_attributes.dos_header_normal_ == true &&
	!data_container.diarelist.empty()) {
		return true;
	}
	else {
		return false;
	}
}

/* public */
bool ReInspector::dosheader_recheck(Structuresults& data_container) {
	return true;
}

bool ReInspector::dosstub_recheck(Structuresults& data_container) {
	return true;
}

bool ReInspector::file_header_recheck(Structuresults& data_container) {
	return true;
}

bool ReInspector::optional_header_recheck(Structuresults& data_container) {
	return true;
}

bool ReInspector::section_headers_recheck(Structuresults& data_container) {
	return true;
}

bool ReInspector::INT_extract(std::ifstream& pedata, Structuresults& data_container) {
	if (!check_data_nonempty(data_container) ||
	!data_container.structures_attributes.import_descriptor_found_) {
		return false;
	}

	for (size_t i = 0; i < data_container.import_descriptor.size(); i++) {

	}

	return true;
}