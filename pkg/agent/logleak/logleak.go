// Package logleak finds captured content in a rendered log, in any encoding
// a log line could carry it in. Tests plant a body or a query value, run a
// capture path with a debug logger from Logger, and assert Find comes back
// empty: the capture paths log a length, a content type or a name, never the
// bytes.
package logleak

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Window is the run Find looks for: any Window bytes of an encoding. A
// shorter run matches by chance.
const Window = 8

// Encodings is every form a log line could carry content in: as it is,
// quoted or JSON-escaped, URL-escaped, as hex (also spaced, as hex.Dump and
// "% x" write it), as hex.Dump's text column, as Go prints a []byte, and as
// base64 in each alphabet from each of its three alignments (base64 of a
// slice that starts at a byte offset not a multiple of 3 shares no text with
// the base64 of the whole). hex.Dump's offsets and padding are not content,
// so its two columns are looked for, not its output whole: an offset
// "00000000" or a run of spaces in a log is no leak.
func Encodings(content []byte) map[string]string {
	quoted, _ := json.Marshal(string(content))
	enc := map[string]string{
		"raw":          string(content),
		"quoted":       strconv.Quote(string(content)),
		"json":         string(quoted),
		"query-escape": url.QueryEscape(string(content)),
		"path-escape":  url.PathEscape(string(content)),
		"hex":          hex.EncodeToString(content),
		"HEX":          strings.ToUpper(hex.EncodeToString(content)),
		"%v":           fmt.Sprintf("%v", content),
		"spaced hex":   fmt.Sprintf("% x", content),
		"dump text":    dumpText(content),
		"%q of []byte": fmt.Sprintf("%q", content),
	}
	for name, e := range map[string]*base64.Encoding{"std": base64.StdEncoding, "url": base64.URLEncoding, "rawstd": base64.RawStdEncoding, "rawurl": base64.RawURLEncoding} {
		for shift := 0; shift < 3 && shift < len(content); shift++ {
			enc[fmt.Sprintf("base64 %s from byte %d", name, shift)] = e.EncodeToString(content[shift:])
		}
	}
	return enc
}

// dumpText is hex.Dump's text column: each byte printable in ASCII as it is,
// any other as '.'.
func dumpText(content []byte) string {
	out := make([]byte, len(content))
	for i, c := range content {
		if c < 32 || c > 126 {
			c = '.'
		}
		out[i] = c
	}
	return string(out)
}

// Find names each encoding of content that has a Window-byte run in log,
// with the run found, sorted. Content shorter than Window is looked for
// whole, and empty content is never found: there is nothing to leak.
func Find(log string, content []byte) []string {
	if len(content) == 0 {
		return nil
	}
	var found []string
	for name, e := range Encodings(content) {
		w := min(Window, len(e))
		for i := 0; i+w <= len(e); i++ {
			if s := e[i : i+w]; strings.Contains(log, s) {
				found = append(found, fmt.Sprintf("%s: %q", name, s))
				break
			}
		}
	}
	sort.Strings(found)
	return found
}

// Buffer is a rendered log, safe to write from many goroutines.
type Buffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// Sync is a no-op: the log is in memory.
func (b *Buffer) Sync() error { return nil }

func (b *Buffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Logger is a Debug logger that renders each entry as production renders
// it, as JSON and as console text, into the Buffer it returns, and passes
// each entry to also (an observer core, say) when it is not nil.
func Logger(also zapcore.Core) (*zap.Logger, *Buffer) {
	out := &Buffer{}
	cfg := zap.NewProductionEncoderConfig()
	cores := []zapcore.Core{
		zapcore.NewCore(zapcore.NewJSONEncoder(cfg), out, zap.DebugLevel),
		zapcore.NewCore(zapcore.NewConsoleEncoder(cfg), out, zap.DebugLevel),
	}
	if also != nil {
		cores = append(cores, also)
	}
	return zap.New(zapcore.NewTee(cores...)), out
}
