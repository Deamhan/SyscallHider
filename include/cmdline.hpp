#pragma once

#include <string>
#include <vector>
#include <utility>

typedef std::pair<std::string, bool> CmdLineOptionValue;

struct CmdLineOption
{
	char shortNotation;
	std::string_view longNotation;
	std::string_view description;
	std::string_view defaultValue;
	bool isMandatory;
	CmdLineOptionValue& outValue;
};

void ParseCmdLine(const std::vector<CmdLineOption>& opts, int argc, const char** argv);
