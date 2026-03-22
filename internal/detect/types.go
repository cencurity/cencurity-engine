package detect

// ContentContext captures shallow output context for policy decisions.
type ContentContext string

const (
	// ContentContextPlain describes ordinary explanatory text.
	ContentContextPlain ContentContext = "plain"
	// ContentContextInlineCode describes inline-code-like text.
	ContentContextInlineCode ContentContext = "inline_code"
	// ContentContextCodeBlock describes fenced or strongly code-like output.
	ContentContextCodeBlock ContentContext = "code_block"
)

// Detection describes a pattern match found in model output.
type Detection struct {
	RuleID   string
	Category string
	Severity string
	Action   string
	Match    string
	Start    int
	End      int
	Mode     string
	Priority int
}
