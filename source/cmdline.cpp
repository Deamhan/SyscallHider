#include "cmdline.hpp"

#include <algorithm>
#include <cstdio>
#include <numeric>
#include <stdexcept>

static void ShowHelp(const std::vector<CmdLineOption>& opts)
{
	printf("Help:\n");
	unsigned maxLen = std::accumulate(opts.begin(), opts.end(), 0u, [](unsigned value, const CmdLineOption& opt) 
		{ 
			return std::max<unsigned>(value, opt.longNotation.length()); 
		});

	for (const auto& opt : opts)
	{
		printf("\t-%c | --%-*s : %s, default value is \'%s\'\n", opt.shortNotation, maxLen, opt.longNotation.c_str(),
			opt.description.c_str(), opt.defaultValue.c_str());
	}

	printf("\n");
}

void ParseCmdLine(const std::vector<CmdLineOption>& opts, int argc, const char** argv)
{
	const CmdLineOption* selectedOpt = nullptr;
	for (size_t i = 1; i < argc; ++i)
	{
		const std::string arg(argv[i]);
		if (arg.compare(0, 1, "-") == 0)
		{
			if (selectedOpt != nullptr)
				throw std::logic_error(std::string("option hasn't been set: ").append(selectedOpt->longNotation));

			if (arg.compare(0, 2, "--") == 0)
			{
				for (auto& opt : opts)
				{
					if (0 == arg.compare(2, std::wstring::npos, opt.longNotation))
					{
						selectedOpt = &opt;
						break;
					}
				}
			}
			else if (arg.length() == 2)
			{
				for (auto& opt : opts)
				{
					if (arg[1] == opt.shortNotation)
					{
						selectedOpt = &opt;
						break;
					}
				}
			}

			if (selectedOpt == nullptr)
				throw std::logic_error(std::string("unknown cmd line option: ").append(arg));

			if (selectedOpt->outValue.second)
				throw std::logic_error(std::string("option redifinition if not allowed: ").append(selectedOpt->longNotation));

			continue;
		}

	    if (selectedOpt == nullptr)
	    	throw std::logic_error(std::string("option hasn't been selected before \'").append(arg).append("\'"));
	    
	    selectedOpt->outValue.first = arg;
	    selectedOpt->outValue.second = true;
	    selectedOpt = nullptr;
	}

	for (auto& opt : opts)
	{
		if (!opt.outValue.second)
		{
			if (opt.isMandatory)
			{
				ShowHelp(opts);
				throw std::logic_error(std::string("mandatory option is not provided: ").append(opt.longNotation));
			}

			opt.outValue.first = opt.defaultValue;
		}
	}
}
