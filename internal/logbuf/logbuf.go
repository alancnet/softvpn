// Package logbuf keeps the most recent log records in memory, for the web
// UI's log view: a slog handler that passes every record on to another
// handler and also stores it in a ring buffer.
package logbuf

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Entry is one stored log record.
type Entry struct {
	Seq   uint64    `json:"seq"`
	Time  time.Time `json:"time"`
	Level string    `json:"level"`
	Msg   string    `json:"msg"`
	Attrs string    `json:"attrs"` // key=value pairs, as the text handler writes them
}

// Ring holds the last Size entries.
type Ring struct {
	mu      sync.Mutex
	entries []Entry
	next    int // index of the next write once full
	seq     uint64
	notify  chan struct{} // closed and replaced on every write
}

// New returns a ring buffer of size entries.
func New(size int) *Ring {
	return &Ring{entries: make([]Entry, 0, size), notify: make(chan struct{})}
}

func (r *Ring) add(e Entry) {
	r.mu.Lock()
	r.seq++
	e.Seq = r.seq
	if len(r.entries) < cap(r.entries) {
		r.entries = append(r.entries, e)
	} else {
		r.entries[r.next] = e
		r.next = (r.next + 1) % len(r.entries)
	}
	close(r.notify)
	r.notify = make(chan struct{})
	r.mu.Unlock()
}

// Since returns the stored entries with a sequence number above seq, oldest
// first, and a channel that is closed when another entry arrives.
func (r *Ring) Since(seq uint64) ([]Entry, <-chan struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Entry
	n := len(r.entries)
	for i := 0; i < n; i++ {
		e := r.entries[(r.next+i)%n]
		if e.Seq > seq {
			out = append(out, e)
		}
	}
	return out, r.notify
}

// Handler returns a slog handler that stores records at or above level in
// the ring and passes every record to next.
func (r *Ring) Handler(next slog.Handler, level slog.Leveler) slog.Handler {
	return &tee{ring: r, next: next, level: level}
}

type tee struct {
	ring   *Ring
	next   slog.Handler
	level  slog.Leveler
	attrs  string // from WithAttrs, preformatted
	prefix string // from WithGroup: "group."
}

func (t *tee) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= t.level.Level() || t.next.Enabled(ctx, l)
}

func (t *tee) Handle(ctx context.Context, rec slog.Record) error {
	if rec.Level >= t.level.Level() {
		var b strings.Builder
		b.WriteString(t.attrs)
		rec.Attrs(func(a slog.Attr) bool {
			appendAttr(&b, t.prefix, a)
			return true
		})
		t.ring.add(Entry{Time: rec.Time, Level: rec.Level.String(), Msg: rec.Message, Attrs: strings.TrimSpace(b.String())})
	}
	if t.next.Enabled(ctx, rec.Level) {
		return t.next.Handle(ctx, rec)
	}
	return nil
}

func (t *tee) WithAttrs(as []slog.Attr) slog.Handler {
	n := *t
	var b strings.Builder
	b.WriteString(t.attrs)
	for _, a := range as {
		appendAttr(&b, t.prefix, a)
	}
	n.attrs = b.String()
	n.next = t.next.WithAttrs(as)
	return &n
}

func (t *tee) WithGroup(name string) slog.Handler {
	if name == "" {
		return t
	}
	n := *t
	n.prefix = t.prefix + name + "."
	n.next = t.next.WithGroup(name)
	return &n
}

func appendAttr(b *strings.Builder, prefix string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return
	}
	if a.Value.Kind() == slog.KindGroup {
		p := prefix
		if a.Key != "" {
			p += a.Key + "."
		}
		for _, g := range a.Value.Group() {
			appendAttr(b, p, g)
		}
		return
	}
	v := a.Value.String()
	if v == "" || strings.ContainsAny(v, " \t\"=") {
		v = fmt.Sprintf("%q", v)
	}
	b.WriteString(" " + prefix + a.Key + "=" + v)
}
