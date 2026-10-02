package logbuf

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestRingTee(t *testing.T) {
	var out bytes.Buffer
	var level slog.LevelVar
	r := New(3)
	log := slog.New(r.Handler(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: &level}), &level))
	log.Debug("hidden")
	log.With("client", "alice").Info("connected", "ip", "10.8.0.2", "note", "two words")
	log.Warn("w1")
	log.Error("e1")
	log.Info("i2")

	entries, notify := r.Since(0)
	if len(entries) != 3 {
		t.Fatalf("kept %d entries, want the last 3", len(entries))
	}
	if entries[0].Msg != "w1" || entries[2].Msg != "i2" || entries[2].Seq != 4 {
		t.Fatalf("entries %+v", entries)
	}
	if !strings.Contains(out.String(), "msg=connected client=alice ip=10.8.0.2") || strings.Contains(out.String(), "hidden") {
		t.Fatalf("text handler output:\n%s", out.String())
	}
	all := New(10)
	l2 := slog.New(all.Handler(slog.NewTextHandler(&out, nil), &level))
	l2.With("client", "alice").Info("connected", "note", "two words")
	e, _ := all.Since(0)
	if e[0].Attrs != `client=alice note="two words"` || e[0].Level != "INFO" {
		t.Fatalf("attrs %q", e[0].Attrs)
	}

	if got, _ := r.Since(3); len(got) != 1 || got[0].Msg != "i2" {
		t.Fatalf("Since(3) = %+v", got)
	}
	select {
	case <-notify:
		t.Fatal("notified without a new entry")
	default:
	}
	log.Info("more")
	select {
	case <-notify:
	default:
		t.Fatal("not notified of a new entry")
	}
}
