package detect

import "regexp"

func langChainProfile() frameworkProfile {
	return frameworkProfile{
		Name:     "langchain",
		Language: LanguagePython,
		Tier:     TierMedium,
		Indicators: []*regexp.Regexp{regexp.MustCompile(`(?is)from\s+langchain|langchain\.|@tool|Tool\(|AgentExecutor|create_react_agent`)},
		Rules: []frameworkRule{
			makeRule("cast.langchain.tool.exec-from-input", "dangerous_execution", "dangerous-code", "high", "block", `(?is)(@tool|Tool\(|from\s+langchain).{0,260}(subprocess\.(run|Popen)|os\.system)\(.{0,220}(input|query|question|prompt|tool_input)`),
			makeRule("cast.langchain.fetch-from-input", "ssrf", "app-vulnerability", "high", "block", `(?is)(url|target)\s*=.{0,180}(input|query|question|prompt|tool_input|state\[).{0,220}\n.{0,260}(requests\.(get|post)|httpx\.(get|post|request))\((url|target)`),
			makeRule("cast.langchain.file-from-input", "path_traversal", "app-vulnerability", "high", "block", `(?is)(path|filename)\s*=.{0,180}(input|query|question|prompt|tool_input|state\[).{0,220}\n.{0,220}(open|Path)\((path|filename)`),
		},
	}
}

func langGraphProfile() frameworkProfile {
	return frameworkProfile{
		Name:     "langgraph",
		Language: LanguagePython,
		Tier:     TierDeep,
		Indicators: []*regexp.Regexp{regexp.MustCompile(`(?is)from\s+langgraph|langgraph\.|StateGraph\(|MessagesState|builder\.add_node|Command\(|ToolNode|interrupt\(`)},
		Rules: []frameworkRule{
			makeRule("cast.langgraph.exec-from-state", "dangerous_execution", "dangerous-code", "high", "block", `(?is)state\[['"](input|query|command|prompt)['"]\].{0,220}\n.{0,260}(subprocess\.(run|Popen)|os\.system)\(`),
			makeRule("cast.langgraph.fetch-from-state", "ssrf", "app-vulnerability", "high", "block", `(?is)(url|target)\s*=\s*state\[['"](url|target|input|query)['"]\].{0,220}\n.{0,260}(requests\.(get|post)|httpx\.(get|post|request))\((url|target)`),
			makeRule("cast.langgraph.file-from-state", "path_traversal", "app-vulnerability", "high", "block", `(?is)(path|filename)\s*=\s*state\[['"](path|file|input)['"]\].{0,220}\n.{0,220}(open|Path)\((path|filename)`),
			makeRule("cast.langgraph.exec-from-messages", "dangerous_execution", "dangerous-code", "high", "block", `(?is)((messages|state\[['"]messages['"]\]).{0,260}(subprocess\.(run|Popen)|os\.system)\(|(subprocess\.(run|Popen)|os\.system)\(.{0,260}(messages|state\[['"]messages['"]\]))`),
			makeRule("cast.langgraph.command-from-state", "dangerous_execution", "dangerous-code", "high", "block", `(?is)(cmd|command)\s*=\s*state\[['"](cmd|command|input|query)['"]\].{0,220}\n.{0,220}(subprocess\.(run|Popen)|os\.system)\((cmd|command)`),
			makeRule("cast.langgraph.toolnode-untrusted-state", "framework_misuse", "framework-misuse", "high", "block", `(?is)ToolNode\(.{0,260}state\[['"](tools|input|command|query)['"]`),
			makeRule("cast.langgraph.command-goto-from-input", "framework_misuse", "framework-misuse", "high", "block", `(?is)Command\(.{0,220}goto\s*=\s*state\[['"](next|goto|route|step)['"]`),
			makeRule("cast.langgraph.interrupt-from-state", "framework_misuse", "framework-misuse", "medium", "block", `(?is)interrupt\(.{0,220}state\[['"](input|query|prompt|message)['"]`),
		},
	}
}
