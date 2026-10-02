package config

import (
	"strings"
)

// Line is one line of a configuration file as written, for editors that
// change some directives and must keep everything else (comments, blank
// lines, order, inline blocks) exactly as it was.
type Line struct {
	Raw   string   // the line without its newline
	Name  string   // directive name, lower case; "" for comments, blank lines and inline blocks
	Args  []string // directive arguments
	Block string   // the inline block this line opens, closes or is inside; "" outside blocks
}

// SplitLines splits configuration text into lines. A line that does not
// tokenize (an unterminated quote) is kept as an unnamed line; the parser
// reports it.
func SplitLines(text string) []Line {
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return nil
	}
	var out []Line
	block := ""
	for _, raw := range strings.Split(text, "\n") {
		raw = strings.TrimSuffix(raw, "\r")
		l := Line{Raw: raw}
		t := strings.TrimSpace(raw)
		switch {
		case block != "":
			l.Block = block
			if t == "</"+block+">" {
				block = ""
			}
		case t == "" || t[0] == '#' || t[0] == ';':
		case strings.HasPrefix(t, "<") && strings.HasSuffix(t, ">") && !strings.HasPrefix(t, "</"):
			block = strings.TrimSuffix(strings.TrimPrefix(t, "<"), ">")
			l.Block = block
		default:
			if f, err := tokenize(t); err == nil && len(f) > 0 {
				l.Name, l.Args = strings.ToLower(f[0]), f[1:]
			}
		}
		out = append(out, l)
	}
	return out
}

// JoinLines is the inverse of SplitLines: the text, newline-terminated.
func JoinLines(lines []Line) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.Raw)
		b.WriteByte('\n')
	}
	return b.String()
}

// FormatDirective renders a directive line, quoting arguments that need it.
func FormatDirective(name string, args ...string) string {
	var b strings.Builder
	b.WriteString(name)
	for _, a := range args {
		b.WriteByte(' ')
		b.WriteString(Quote(a))
	}
	return b.String()
}

// Quote returns a as a single configuration token.
func Quote(a string) string {
	if a != "" && !strings.ContainsAny(a, " \t\"\\#;'") {
		return a
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(a) + `"`
}
