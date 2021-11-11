#include "cmdline.hpp"

#include <stdexcept>

void ParseCmdLine(const std::vector<CmdLineOption>& opts, int argc, const char** argv)
{
	const CmdLineOption* selectedOpt = nullptr;
	for (size_t i = 1; i < argc; ++i)
	{
		const std::string arg(argv[i]);
		if (arg.compare(0, 1, "-"))
		{
			if (selectedOpt != nullptr)
				throw std::logic_error(std::string("option redifinition if not allowed: ").append(selectedOpt->longNotation).append(" to ").append(arg));

			if (arg.compare(0, 2, "--"))
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
			else if (arg.length() == 3)
			{
				for (auto& opt : opts)
				{
					if (arg[2] == opt.shortNotation)
					{
						selectedOpt = &opt;
						break;
					}
				}
			}

			if (selectedOpt == nullptr)
				throw std::logic_error(std::string("unknown cmd line option: ").append(arg));

			if (selectedOpt == nullptr)
				throw std::logic_error(std::string("option hasn't been selected before \'").append(arg).append("\'"));

			selectedOpt->outValue.first = arg;
			selectedOpt->outValue.second = true;
			selectedOpt = nullptr;
		}
	}

	for (auto& opt : opts)
	{
		if (opt.outValue.second)
		{
			if (opt.isMandatory)
				throw std::logic_error(std::string("mandatory option is not provided: ").append(opt.longNotation));

			opt.outValue.first = opt.defaultValue;
		}
	}
}
