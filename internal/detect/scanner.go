package detect

import (
	"sort"
	"strconv"
	"strings"

	"cencurity-engine/internal/rules"
)

var rawPrefilterTokens = []string{
	"sk", "xai", "gh", "akia", "aiza", "xox",
	"api_key", "apikey", "token", "secret", "password", "client_secret", "access_key",
	"eval", "exec", "private", "begin", "os.", "subprocess",
	"langchain", "langgraph", "@tool", "stategraph", "subprocess.run", "torch.load", "read_pickle", "allow_pickle",
	"shell", "curl", "wget", "base64", "powershell", "cmd.", "/bin/sh",
	"select", "insert", "update", "delete", "query(", "execute(",
	"innerhtml", "dangerouslysetinnerhtml", "v-html", "render_template_string", "nextrequest", "searchparams", "next_public_",
	"csrf", "csrf_exempt", "verify_authenticity_token", "permitall", "allowany",
	"requests.get", "requests.post", "http.get", "axios.get", "fetch(", "urlopen(",
	"run:", "command:", "script:", "payload:", "tailwind.config", "safelist", "route.query",
	"filepath.join", "send_file", "sendfile", "../", "verify=false", "insecureskipverify",
	"isadmin", "admin= true", "admin=true", "skip_authorization",
	"fastapi", "request.query_params", "request.path_params", "request.headers", "request.cookies", "request.json(",
	"htmlresponse", "fileresponse", "templateresponse", "httpx.get", "httpx.post", "verify_signature", "corsmiddleware", "allow_origins",
	"express-session", "cookie-session", "saveuninitialized", "httponly", "samesite", "res.cookie",
	"req.session", "session.user", "session.role", "session.isadmin",
	"jwt.decode", "jwt.verify", "authorization", "bearer ", "passport", "req.user",
	"passport.authenticate", "passport.use", "req.isauthenticated", "req.login", "serializeuser", "deserializeuser",
	"sequelize.query", "sequelize.literal", "prisma.$queryrawunsafe", "prisma.$executeRawUnsafe", "knex.raw",
	"multer", "diskstorage", "originalname", "upload.single", "upload.array",
}

var compactPrefilterTokens = []string{
	"sk", "xai", "gh", "akia", "aiza", "xox",
	"apikey", "token", "secret", "password", "clientsecret", "accesskey",
	"eval", "exec", "beginprivatekey", "ossystem", "subprocess",
	"langchain", "langgraph", "tool", "stategraph", "subprocessrun", "torchload", "readpickle", "allowpickle",
	"shelltrue", "curlsh", "wgetsh", "base64", "powershellexe", "cmdexe", "binsh",
	"select", "insert", "update", "delete", "query", "execute",
	"innerhtml", "dangerouslysetinnerhtml", "rendertemplatestring", "nextrequest", "searchparams", "nextpublic",
	"csrf", "csrfexempt", "verifyauthenticitytoken", "permitall", "allowany",
	"requestsget", "requestspost", "httpget", "axiosget", "fetch", "urlopen",
	"run", "command", "script", "payload", "tailwindconfig", "safelist", "routequery",
	"filepathjoin", "sendfile", "verifyfalse", "insecureskipverify",
	"skipauthorization", "isadmin", "roleadmin", "admintrue",
	"fastapi", "requestqueryparams", "requestpathparams", "requestheaders", "requestcookies", "requestjson",
	"htmlresponse", "fileresponse", "templateresponse", "httpxget", "httpxpost", "verifysignature", "corsmiddleware", "alloworigins",
	"expresssession", "cookiesession", "saveuninitialized", "httponly", "samesite", "rescookie",
	"reqsession", "sessionuser", "sessionrole", "sessionisadmin",
	"jwtdecode", "jwtverify", "authorization", "bearer", "passport", "requser",
	"passportauthenticate", "passportuse", "reqisauthenticated", "reqlogin", "serializeuser", "deserializeuser",
	"sequelizequery", "sequelizeliteral", "prismaqueryrawunsafe", "prismaexecuterawunsafe", "knexraw",
	"multer", "diskstorage", "originalname", "uploadsingle", "uploadarray",
}

// Scanner inspects current output chunks with short historical context.
type Scanner struct {
	rules *rules.Manager
}

// NewScanner creates a detector using precompiled patterns.
func NewScanner(manager *rules.Manager) *Scanner {
	return &Scanner{rules: manager}
}

// ShouldScan returns true only when cheap prefiltering suggests a suspicious chunk.
func (s *Scanner) ShouldScan(prefixTail, chunk string) bool {
	if chunk == "" {
		return false
	}
	rawCombined := strings.ToLower(prefixTail + chunk)
	for _, token := range rawPrefilterTokens {
		if strings.Contains(rawCombined, token) {
			return true
		}
	}
	compact := CompactNormalize(prefixTail + chunk).Text
	for _, token := range compactPrefilterTokens {
		if strings.Contains(compact, token) {
			return true
		}
	}
	return false
}

// Scan evaluates the current chunk against the prefix window and returns matches.
func (s *Scanner) Scan(prefix, chunk string) []Detection {
	if chunk == "" {
		return nil
	}

	results := make([]Detection, 0, 4)
	seen := make(map[string]struct{})
	rawCombined := prefix + chunk
	rawPrefixLength := len(prefix)
	rawChunkEnd := rawPrefixLength + len(chunk)
	compactPrefix := CompactNormalize(prefix)
	compactChunk := CompactNormalize(chunk)
	compactCombinedText := compactPrefix.Text + compactChunk.Text
	compactChunkStart := len(compactPrefix.Text)
	compactChunkEnd := len(compactCombinedText)

	for _, item := range s.rules.Rules() {
		var searchText string
		var chunkStart int
		var chunkEnd int
		switch item.Mode {
		case "compact":
			searchText = compactCombinedText
			chunkStart = compactChunkStart
			chunkEnd = compactChunkEnd
		default:
			searchText = rawCombined
			chunkStart = rawPrefixLength
			chunkEnd = rawChunkEnd
		}

		indices := item.Regex.FindAllStringIndex(searchText, -1)
		for _, index := range indices {
			start := index[0]
			end := index[1]
			if end <= chunkStart || start >= chunkEnd {
				continue
			}

			currentStart := max(start, chunkStart) - chunkStart
			currentEnd := min(end, chunkEnd) - chunkStart
			if currentStart >= currentEnd {
				continue
			}

			mappedStart, mappedEnd, match := mapDetection(item.Mode, chunk, compactChunk, currentStart, currentEnd)
			if match == "" || mappedStart >= mappedEnd {
				continue
			}
			key := item.ID + ":" + match + ":" + strconv.Itoa(mappedStart) + ":" + strconv.Itoa(mappedEnd)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}

			results = append(results, Detection{
				RuleID:   item.ID,
				Category: item.Category,
				Severity: item.Severity,
				Action:   item.Action,
				Match:    match,
				Start:    mappedStart,
				End:      mappedEnd,
				Mode:     item.Mode,
				Priority: item.Priority,
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Start == results[j].Start {
			return results[i].End < results[j].End
		}
		return results[i].Start < results[j].Start
	})

	return results
}

func mapDetection(mode, chunk string, compactChunk NormalizedText, start, end int) (int, int, string) {
	if mode != "compact" {
		return start, end, chunk[start:end]
	}
	if len(compactChunk.Offset) == 0 || start >= len(compactChunk.Offset) {
		return 0, 0, ""
	}
	if end > len(compactChunk.Offset) {
		end = len(compactChunk.Offset)
	}
	startByte := compactChunk.Offset[start]
	endByte := compactChunk.Offset[end-1] + 1
	if endByte > len(chunk) {
		endByte = len(chunk)
	}
	if startByte >= endByte {
		return 0, 0, ""
	}
	return startByte, endByte, chunk[startByte:endByte]
}

func max(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}
