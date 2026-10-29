package logleak

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Find finds content in each encoding it lists, and nothing in a log that
// gives only its length.
func TestFindFindsEachEncodingAndNothingElse(t *testing.T) {
	content := []byte("token=sk_live_9fQ2xLp7&email=ada@example.com\x00\xff")
	for name, e := range Encodings(content) {
		// Each encoding cut to an inner stretch: Find must not need the whole.
		inner := e[len(e)/4 : len(e)/4+Window+3]
		log := `{"msg":"x","v":"` + inner + `"}`
		found := Find(log, content)
		if len(found) == 0 {
			t.Errorf("%s: Find missed %q in %s", name, inner, log)
		}
	}
	if found := Find(`{"msg":"read the request","bytes":47}`, content); len(found) != 0 {
		t.Errorf("Find found content in a log that gives its length only: %v", found)
	}
}

// Find reports content, not the frame an encoding puts around it: a log
// holding a hex.Dump's offset ("00000000") or a run of padding spaces holds no
// content, and empty content is found nowhere. A hex.Dump of the content is
// found by its columns.
func TestFindReportsNoFrameAndNoEmptyContent(t *testing.T) {
	content := []byte("token=sk_live_9fQ2xLp7&email=ada@example.com\x00\xff")
	for _, log := range []string{
		`{"msg":"x","traceID":"00000000000000000000000000000000"}`,
		"x\t        \t        indented        text",
	} {
		if found := Find(log, content); len(found) != 0 {
			t.Errorf("Find found content in %q: %v", log, found)
		}
	}
	if found := Find(`{"msg":"x"}`, nil); len(found) != 0 {
		t.Errorf("Find found empty content: %v", found)
	}
	if found := Find(`{"msg":"x","dump":"`+hex.Dump(content)+`"}`, content); len(found) == 0 {
		t.Error("Find missed a hex.Dump of the content")
	}
}

// Logger renders each entry twice, as JSON and as console text.
func TestLoggerRendersJSONAndConsole(t *testing.T) {
	logger, out := Logger(nil)
	logger.Debug("planted line")
	if got := strings.Count(out.String(), "planted line"); got != 2 {
		t.Fatalf("the line is rendered %d times, want 2 (JSON and console): %s", got, out.String())
	}
}
