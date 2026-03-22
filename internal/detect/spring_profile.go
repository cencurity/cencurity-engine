package detect

import "regexp"

func springProfile() frameworkProfile {
	return frameworkProfile{
		Name:     "spring",
		Language: LanguageJava,
		Tier:     TierLight,
		Indicators: []*regexp.Regexp{regexp.MustCompile(`(?is)org\.springframework|@RestController|HttpSecurity|permitAll\(|@RequestParam`)},
		Rules: []frameworkRule{
			makeRule("cast.spring.sqli", "sql_injection", "app-vulnerability", "high", "block", `(?is)@RequestParam.{0,160}\n.{0,240}(jdbcTemplate\.(query|update)|createNativeQuery|entityManager\.createQuery).{0,240}(select|update|delete|insert)`),
			makeRule("cast.spring.authz", "auth_misuse", "auth-misuse", "high", "block", `(?is)anyRequest\(\)\.permitAll\(|requestMatchers\([^\n]{0,160}\)\.permitAll\(`),
			makeRule("cast.spring.csrf-disabled", "csrf", "framework-misuse", "high", "block", `(?is)csrf\([^\n]{0,120}disable\(`),
		},
	}
}
