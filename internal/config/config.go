// Package config parses OpenVPN-style configuration.
//
// A configuration is a list of directives, one per line:
//
//	# comment
//	remote vpn.example.com 1194
//	forward tcp 127.0.0.1:5432 db.internal:5432
//
// Key material can be inlined the same way .ovpn profiles do it:
//
//	<ca>
//	-----BEGIN CERTIFICATE-----
//	...
//	</ca>
//
// The same directives can be given on the command line as --name arg...,
// and "--config FILE" splices a file in at that position. Later directives
// override earlier single-valued ones, so command-line flags placed after
// --config win.
package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Directive is a single configuration statement.
type Directive struct {
	Name string
	Args []string
	Pos  string // "file:line" or "argv", for error messages
	dir  string // directory relative file paths are resolved against
}

func (d Directive) Errorf(format string, a ...any) error {
	return fmt.Errorf("%s: %s: %s", d.Pos, d.Name, fmt.Sprintf(format, a...))
}

// Arg returns argument i or "" if absent.
func (d Directive) Arg(i int) string {
	if i < len(d.Args) {
		return d.Args[i]
	}
	return ""
}

// Path returns argument i as a file name, resolved against the directory of
// the file the directive came from.
func (d Directive) Path(i int) string {
	if a := d.Arg(i); a != "" && d.dir != "" {
		return resolve(d.dir, a)
	}
	return d.Arg(i)
}

// Config is an ordered set of directives plus inline blocks.
type Config struct {
	Directives []Directive
	Inline     map[string]string
}

func New() *Config { return &Config{Inline: map[string]string{}} }

// ParseFile reads a configuration file.
func ParseFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	c := New()
	if err := c.parse(f, path, filepath.Dir(path)); err != nil {
		return nil, err
	}
	return c, nil
}

// ParseString parses configuration text (used by tests and generated profiles).
func ParseString(s string) (*Config, error) {
	c := New()
	return c, c.parse(strings.NewReader(s), "<string>", ".")
}

func (c *Config) parse(r io.Reader, source, dir string) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	line := 0
	var inline string
	var inlineBody strings.Builder
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		pos := fmt.Sprintf("%s:%d", source, line)
		if inline != "" {
			if text == "</"+inline+">" {
				c.Inline[inline] = inlineBody.String()
				inline = ""
				inlineBody.Reset()
				continue
			}
			inlineBody.WriteString(sc.Text())
			inlineBody.WriteByte('\n')
			continue
		}
		if text == "" || text[0] == '#' || text[0] == ';' {
			continue
		}
		if strings.HasPrefix(text, "<") && strings.HasSuffix(text, ">") && !strings.HasPrefix(text, "</") {
			inline = strings.TrimSuffix(strings.TrimPrefix(text, "<"), ">")
			continue
		}
		fields, err := tokenize(text)
		if err != nil {
			return fmt.Errorf("%s: %w", pos, err)
		}
		d := Directive{Name: strings.ToLower(fields[0]), Args: fields[1:], Pos: pos, dir: dir}
		if d.Name == "config" {
			if len(d.Args) != 1 {
				return d.Errorf("expects one file name")
			}
			sub, err := ParseFile(resolve(dir, d.Args[0]))
			if err != nil {
				return err
			}
			c.merge(sub)
			continue
		}
		c.Directives = append(c.Directives, d)
	}
	if inline != "" {
		return fmt.Errorf("%s: unterminated <%s> block", source, inline)
	}
	return sc.Err()
}

func (c *Config) merge(o *Config) {
	c.Directives = append(c.Directives, o.Directives...)
	for k, v := range o.Inline {
		c.Inline[k] = v
	}
}

// ParseArgs turns "--name a b --other c" into directives. "--config FILE"
// loads FILE at that position.
func ParseArgs(args []string) (*Config, error) {
	c := New()
	cwd, _ := os.Getwd()
	for i := 0; i < len(args); {
		a := args[i]
		if !strings.HasPrefix(a, "--") || len(a) == 2 {
			return nil, fmt.Errorf("argv: unexpected argument %q (options look like --name value)", a)
		}
		d := Directive{Name: strings.ToLower(a[2:]), Pos: "argv", dir: cwd}
		i++
		for i < len(args) && !strings.HasPrefix(args[i], "--") {
			d.Args = append(d.Args, args[i])
			i++
		}
		if d.Name == "config" {
			if len(d.Args) != 1 {
				return nil, d.Errorf("expects one file name")
			}
			sub, err := ParseFile(d.Args[0])
			if err != nil {
				return nil, err
			}
			c.merge(sub)
			continue
		}
		c.Directives = append(c.Directives, d)
	}
	return c, nil
}

// tokenize splits a line on whitespace, honouring double quotes and
// backslash escapes inside them. A trailing # comment is stripped.
func tokenize(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inQuote, have := false, false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case inQuote && ch == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		case ch == '"':
			inQuote = !inQuote
			have = true
		case !inQuote && (ch == ' ' || ch == '\t'):
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		case !inQuote && ch == '#' && !have:
			i = len(s)
		default:
			cur.WriteByte(ch)
			have = true
		}
	}
	if inQuote {
		return nil, fmt.Errorf("unterminated quote")
	}
	if have {
		out = append(out, cur.String())
	}
	return out, nil
}

func resolve(dir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

// Check rejects directives not in known, so typos fail loudly.
func (c *Config) Check(known ...string) error {
	k := map[string]bool{}
	for _, n := range known {
		k[n] = true
	}
	for _, d := range c.Directives {
		if !k[d.Name] {
			return d.Errorf("unknown directive")
		}
	}
	return nil
}

// All returns every directive with the given name, in order.
func (c *Config) All(name string) []Directive {
	var out []Directive
	for _, d := range c.Directives {
		if d.Name == name {
			out = append(out, d)
		}
	}
	return out
}

// Last returns the last directive with the given name.
func (c *Config) Last(name string) (Directive, bool) {
	for i := len(c.Directives) - 1; i >= 0; i-- {
		if c.Directives[i].Name == name {
			return c.Directives[i], true
		}
	}
	return Directive{}, false
}

// Has reports whether a (flag) directive is present.
func (c *Config) Has(name string) bool {
	_, ok := c.Last(name)
	return ok
}

// String returns the first argument of the last directive called name, or def.
func (c *Config) String(name, def string) string {
	if d, ok := c.Last(name); ok && len(d.Args) > 0 {
		return d.Args[0]
	}
	return def
}

// Int returns the integer argument of name, or def.
func (c *Config) Int(name string, def int) (int, error) {
	d, ok := c.Last(name)
	if !ok {
		return def, nil
	}
	n, err := strconv.Atoi(d.Arg(0))
	if err != nil {
		return 0, d.Errorf("expects an integer")
	}
	return n, nil
}

// Seconds parses a duration given either as plain seconds or Go syntax ("30s").
func Seconds(s string) (time.Duration, error) {
	if n, err := strconv.Atoi(s); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return time.ParseDuration(s)
}

// Material returns key material for name: an inline <name> block if present,
// otherwise the contents of the file named by the directive's argument.
func (c *Config) Material(name string) ([]byte, error) {
	b, _, err := c.MaterialArgs(name, 0)
	return b, err
}

// MaterialArgs is Material for directives whose file name may be followed by
// up to extra more arguments ("tls-auth ta.key 0"), which it also returns.
// The file name "[inline]" (older OpenVPN syntax) selects the inline block.
func (c *Config) MaterialArgs(name string, extra int) ([]byte, []string, error) {
	if d, ok := c.Last(name); ok {
		if len(d.Args) < 1 || len(d.Args) > 1+extra {
			if extra == 0 {
				return nil, nil, d.Errorf("expects one file name")
			}
			return nil, nil, d.Errorf("expects a file name and at most %d more argument(s)", extra)
		}
		if d.Args[0] == "[inline]" {
			if v, ok := c.Inline[name]; ok {
				return []byte(v), d.Args[1:], nil
			}
			return nil, nil, d.Errorf("no inline <%s> block", name)
		}
		b, err := os.ReadFile(resolve(d.dir, d.Args[0]))
		if err != nil {
			return nil, nil, d.Errorf("%v", err)
		}
		return b, d.Args[1:], nil
	}
	if v, ok := c.Inline[name]; ok {
		return []byte(v), nil, nil
	}
	return nil, nil, fmt.Errorf("missing %q (give a file with \"%s FILE\" or an inline <%s> block)", name, name, name)
}

// HasMaterial reports whether name is given as a directive or an inline block.
func (c *Config) HasMaterial(name string) bool {
	_, ok := c.Inline[name]
	return ok || c.Has(name)
}
