// Package relay copies data between connection pairs.
package relay

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type closeWriter interface{ CloseWrite() error }

// Stream relays a <-> b until both directions finish, propagating half-closes
// (FIN) where the connection supports it, then closes both.
func Stream(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, 32<<10)
		_, err := io.CopyBuffer(dst, src, buf)
		if cw, ok := dst.(closeWriter); ok && err == nil {
			cw.CloseWrite()
		} else {
			// An error (reset, timeout) in one direction tears down both.
			dst.Close()
			src.Close()
		}
	}
	go pipe(a, b)
	go pipe(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

// Datagram relays packets between two connected datagram sockets until
// neither side has carried traffic for idle, or either side errors.
func Datagram(a, b net.Conn, idle time.Duration) {
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 65535)
		for {
			src.SetReadDeadline(time.Now().Add(idle))
			n, err := src.Read(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, os.ErrDeadlineExceeded) {
					if time.Since(time.Unix(0, last.Load())) < idle {
						continue // the other direction is still active
					}
				}
				return
			}
			last.Store(time.Now().UnixNano())
			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}
		}
	}
	go pipe(a, b)
	go pipe(b, a)
	<-done
	a.Close()
	b.Close()
	<-done
}
