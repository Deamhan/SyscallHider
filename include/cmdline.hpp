#pragma once

#include <stdexcept>
#include <string>
#include <vector>
#include <utility>

typedef std::pair<std::string, bool> CmdLineOptionValue;

struct CmdLineOption
{
	char shortNotation;
	std::string longNotation;
	std::string description;
	std::string defaultValue;
	bool isMandatory;
	CmdLineOptionValue& outValue;
};

void ParseCmdLine(const std::vector<CmdLineOption>& opts, int argc, const char** argv);
