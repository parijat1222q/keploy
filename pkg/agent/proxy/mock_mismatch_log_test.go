// Package proxy — the one agent-wide mock-mismatch log line must not assert a
// negative it never checked.
//
// destination_scope is only meaningful for a report whose parser supplied
// destination evidence. HTTP is the only protocol that does today (nothing
// else records an upstream authority in its mocks), so an unconditional field
// printed a negative verdict on every mongo/mysql/generic/pulsar miss — which
// reads as "we checked, and it was fine" for a check that never ran.
package proxy

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"go.keploy.io/server/v3/pkg/agent/logleak"
	"go.keploy.io/server/v3/pkg/models"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// mismatchLogFields is the fields of the one mock-mismatch line a miss logs.
// Its level is the proven switch's to decide (a WARN with the switch off; at
// Debug under it, where keploy's verdict names each miss): its fields are the
// same either way, so the line is found by its message, at any level, whatever
// switch the test runs under.
func mismatchLogFields(t *testing.T, report *models.MockMismatchReport) map[string]any {
	t.Helper()
	core, logs := observer.New(zap.DebugLevel)
	p := &Proxy{logger: zap.New(core), errChannel: make(chan error, 4)}

	p.sendMockNotFoundError(models.NewMockMismatchError(models.ErrNoMockMatched, report))

	entries := logs.FilterMessageSnippet("mock mismatch: no matching mock for outgoing call").All()
	if len(entries) != 1 {
		t.Fatalf("expected exactly one mismatch log entry, got %d: %v", len(entries), logs.All())
	}
	return entries[0].ContextMap()
}

func TestSendMockNotFoundError_ScopeFieldOmittedWithoutEvidence(t *testing.T) {
	// A Mongo miss: no destination evidence was ever gathered.
	fields := mismatchLogFields(t, &models.MockMismatchReport{
		Protocol:      "MongoDB",
		Destination:   "mongo.example.com:27017",
		ActualSummary: "find users",
		MatchPhase:    models.MatchPhaseExhausted,
	})

	if _, present := fields["destination_scope"]; present {
		t.Errorf("unchecked destination scope must be absent from the log, got %v", fields["destination_scope"])
	}
	if fields["match_phase"] != models.MatchPhaseExhausted {
		t.Errorf("match_phase = %v, want %q", fields["match_phase"], models.MatchPhaseExhausted)
	}
}

func TestSendMockNotFoundError_ScopeFieldReflectsTheVerdict(t *testing.T) {
	for _, scope := range []string{
		models.DestinationScopeNotInComparedSet,
		models.DestinationScopeInComparedSet,
	} {
		t.Run(scope, func(t *testing.T) {
			fields := mismatchLogFields(t, &models.MockMismatchReport{
				Protocol:         "HTTP",
				Destination:      "192.0.2.20",
				ActualSummary:    "GET /v1/metrics",
				MatchPhase:       models.MatchPhaseSchema,
				DestinationScope: scope,
			})
			got, present := fields["destination_scope"]
			if !present {
				t.Fatalf("an answered scope check must be logged; fields: %v", fields)
			}
			if got != scope {
				t.Errorf("destination_scope = %v, want %v", got, scope)
			}
			// The cascade's stopping point survives alongside the verdict.
			if fields["match_phase"] != models.MatchPhaseSchema {
				t.Errorf("match_phase = %v, want %q", fields["match_phase"], models.MatchPhaseSchema)
			}
		})
	}
}

// The mismatch line, logged at WARN with the switch off, names the call as a
// log names it (mismatch.LogCall): an HTTP call by its method and its target's
// shape, a statement with its literals "?", a generic exchange by keploy's
// counts, a DNS question by its type and name, and a call of a protocol keploy
// has no shape for by nothing: the field is left out, not logged empty. No
// stretch of a query value, a path segment's value, a literal or a bound
// parameter appears in the log in any encoding. It logged the summary whole.
func TestSendMockNotFoundError_LogsTheCallInItsShape(t *testing.T) {
	const token, email, account = "sk_live_Q7wZr9Kf", "grace.vault@example.net", "acct_9Lq2Zx7WbN4"
	for _, c := range []struct {
		protocol, summary, want string
	}{
		{"HTTP", "POST /pay/" + account + "?token=" + token + "&email=" + email, "POST /pay/{}?token={}&email={}"},
		{"MySQL", "SELECT id FROM users WHERE email = '" + email + "' AND token = ? params=[" + token + "]", "SELECT id FROM users WHERE email = ? AND token = ?"},
		{"Generic", "opaque TCP exchange (2 request buffer(s), first 40 bytes)", "opaque TCP exchange (2 request buffer(s), first 40 bytes)"},
		{"DNS", "A api.payments.internal.", "A api.payments.internal."},
		{"MongoDB", `find users {"email":"` + email + `","token":"` + token + `"}`, ""},
	} {
		t.Run(c.protocol, func(t *testing.T) {
			obs, logs := observer.New(zapcore.DebugLevel)
			logger, out := logleak.Logger(obs)
			p := &Proxy{logger: logger, errChannel: make(chan error, 4)}
			p.sendMockNotFoundError(models.NewMockMismatchError(models.ErrNoMockMatched, &models.MockMismatchReport{
				Protocol: c.protocol, Destination: "db.internal:3306", ActualSummary: c.summary, MatchPhase: models.MatchPhaseExhausted,
			}))
			entries := logs.FilterMessageSnippet("mock mismatch: no matching mock for outgoing call").All()
			if len(entries) != 1 {
				t.Fatalf("expected exactly one mismatch log entry, got %d: %v", len(entries), logs.All())
			}
			got, present := entries[0].ContextMap()["actual"]
			if c.want == "" && present {
				t.Errorf("a call keploy has no shape for is left out of the line, got actual = %q", got)
			}
			if c.want != "" && got != c.want {
				t.Errorf("actual = %q, want the call's shape %q", got, c.want)
			}
			log := out.String()
			if !strings.Contains(log, "mock mismatch: no matching mock for outgoing call") {
				t.Fatalf("the rendered log is not the one checked: %s", log)
			}
			for what, content := range map[string]string{"the token": token, "the e-mail": email, "the account in the path": account} {
				if found := logleak.Find(log, []byte(content)); len(found) > 0 {
					t.Errorf("the log holds %s: %v", what, found)
				}
			}
		})
	}
}

// The misses keploy drops (made while no test's capture window was open, or
// of a test whose window was never read) are named by the calls as a log
// names them (mismatch.LogCall), a miss with no report by its kind: no
// statement's literal, path value, document or error text of the call is in
// the WARN that says they were dropped. It wrote each one's summary, or its
// error's text, as it was.
func TestLogDroppedMisses_NamesTheCallsByTheirShape(t *testing.T) {
	const email, account, doc, errText = "ada.brgnhf@mail.test", "acct_7Q2xLp9Zr4mW", "zqvkxjwplmtr", "grace.qzvk@mail.test"
	miss := func(protocol, summary string) error {
		return models.ParserError{ParserErrorType: models.ErrMockNotFound, Err: models.ErrNoMockMatched,
			MismatchReport: &models.MockMismatchReport{Protocol: protocol, ActualSummary: summary}}
	}
	errs := []error{
		miss("MySQL", "SELECT * FROM users WHERE email = '"+email+"'"),
		miss("HTTP", "GET /accounts/"+account+"/keys"),
		miss("MongoDB", `find {"token":"`+doc+`"}`),
		models.ParserError{ParserErrorType: models.ErrMockNotFound, Err: errors.New("no mock for " + errText)},
	}
	obs, logs := observer.New(zapcore.DebugLevel)
	logger, out := logleak.Logger(obs)
	p := &Proxy{logger: logger}
	p.logDroppedMisses("mock mismatches dropped", errs)
	lines := logs.FilterMessage("mock mismatches dropped").All()
	if len(lines) != 1 || lines[0].Level != zapcore.WarnLevel {
		t.Fatalf("want one WARN naming the dropped misses; got %v", logs.All())
	}
	want := []interface{}{"SELECT * FROM users WHERE email = ?", "GET /accounts/{}/keys", "a MongoDB call", "a miss with no report (mock not found)"}
	if calls, _ := lines[0].ContextMap()["calls"].([]interface{}); !reflect.DeepEqual(calls, want) {
		t.Errorf("the line names the calls %q; want %q", calls, want)
	}
	for what, content := range map[string]string{"a statement's literal": email, "a path's account": account, "a document's value": doc, "an error's text": errText} {
		if found := logleak.Find(out.String(), []byte(content)); len(found) > 0 {
			t.Errorf("the log holds %s: %v", what, found)
		}
	}
}
