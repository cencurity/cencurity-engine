package detect

import "regexp"

func pandasProfile() frameworkProfile {
	return frameworkProfile{
		Name:     "pandas",
		Language: LanguagePython,
		Tier:     TierLight,
		Indicators: []*regexp.Regexp{regexp.MustCompile(`(?is)import\s+pandas\s+as\s+pd|pd\.(read_|DataFrame)`)},
		Rules: []frameworkRule{
			makeRule("cast.pandas.read-pickle", "dangerous_execution", "dangerous-code", "high", "block", `(?is)pd\.read_pickle\(`),
			makeRule("cast.pandas.remote-fetch", "ssrf", "app-vulnerability", "medium", "block", `(?is)pd\.(read_csv|read_json|read_parquet)\(['"]https?://`),
		},
	}
}

func numpyProfile() frameworkProfile {
	return frameworkProfile{
		Name:     "numpy",
		Language: LanguagePython,
		Tier:     TierLight,
		Indicators: []*regexp.Regexp{regexp.MustCompile(`(?is)import\s+numpy\s+as\s+np|np\.load\(`)},
		Rules: []frameworkRule{
			makeRule("cast.numpy.allow-pickle", "dangerous_execution", "dangerous-code", "high", "block", `(?is)np\.load\(.{0,140}allow_pickle\s*=\s*True`),
		},
	}
}

func tensorFlowProfile() frameworkProfile {
	return frameworkProfile{
		Name:     "tensorflow",
		Language: LanguagePython,
		Tier:     TierLight,
		Indicators: []*regexp.Regexp{regexp.MustCompile(`(?is)import\s+tensorflow|tf\.keras|tensorflow\.`)},
		Rules: []frameworkRule{
			makeRule("cast.tensorflow.shell-misuse", "dangerous_execution", "dangerous-code", "high", "block", `(?is)subprocess\.run\(.{0,160}shell\s*=\s*True`),
			makeRule("cast.tensorflow.remote-fetch", "ssrf", "app-vulnerability", "medium", "block", `(?is)requests\.(get|post)\(['"]https?://.{0,180}(model|weights|checkpoint)`),
		},
	}
}

func pyTorchProfile() frameworkProfile {
	return frameworkProfile{
		Name:     "pytorch",
		Language: LanguagePython,
		Tier:     TierLight,
		Indicators: []*regexp.Regexp{regexp.MustCompile(`(?is)import\s+torch|torch\.load\(`)},
		Rules: []frameworkRule{
			makeRule("cast.pytorch.unsafe-load", "dangerous_execution", "dangerous-code", "high", "block", `(?is)torch\.load\(`),
			makeRule("cast.pytorch.remote-fetch", "ssrf", "app-vulnerability", "medium", "block", `(?is)requests\.(get|post)\(['"]https?://.{0,180}(model|weights|checkpoint)`),
		},
	}
}
