package mismatch

import (
	"fmt"
	"strings"

	"go.keploy.io/server/v3/pkg/models"
)

// A miss report as a log line names it. A log is pasted into issues, shipped
// to collectors and bundled for support. A report's summary, diff and field
// diffs hold the values the application sent and the recording holds (an
// e-mail address in a body, a token in a query, a statement's literals); the
// report file keeps them for the person who reads it. A log line keeps what
// tells the calls apart: the call's shape, the fields that differ, and how
// long their values are.

// LogCall is the call a report names, as a log line names it: its shape
// (models.MissShape), an HTTP or gRPC call by its method and its target's
// shape, with every path segment the report's field diffs or variable
// places name written {} whatever its look, and a statement with its
// literals written "?"; a generic exchange and a DNS question by the summary
// keploy wrote of it (request counts and sizes; a question's type and name,
// a destination's). "" for a call of any other protocol, whose summary may
// hold a key or a document.
func LogCall(r *models.MockMismatchReport) string {
	if r == nil {
		return ""
	}
	if shape := models.MissShape(models.UnmatchedCall{Protocol: r.Protocol, ActualSummary: r.ActualSummary,
		FieldDiffs: r.FieldDiffs, VariablePlaces: r.VariablePlaces}); shape != "" {
		return shape
	}
	switch r.Protocol {
	case ProtocolGeneric, ProtocolDNS:
		return r.ActualSummary
	}
	return ""
}

// LogDiff is how a report's call differs, as a log line says it: each field
// diff by its field's shape (models.FieldShape), how it differs, and how many
// bytes its recorded and live values hold; a generic exchange's diff as
// keploy wrote it (the closest recording's name and its similarity); and any
// other diff, a text that may quote the values, by its length.
func LogDiff(r *models.MockMismatchReport) string {
	switch {
	case r == nil:
		return ""
	case len(r.FieldDiffs) > 0:
		return logFieldDiffs(r.FieldDiffs)
	case r.Diff == "":
		return ""
	case r.Protocol == ProtocolGeneric:
		return r.Diff
	}
	return fmt.Sprintf("%d bytes, in the report", len(r.Diff))
}

// logFieldDiffs is RenderFieldDiffs with each value written as its length.
func logFieldDiffs(diffs []models.MockFieldDiff) string {
	parts := make([]string, 0, len(diffs))
	for _, d := range diffs {
		field := models.FieldShape(d.Path)
		switch d.Kind {
		case models.DiffKindMissingInLive:
			parts = append(parts, fmt.Sprintf("%s: recorded (%d bytes), absent in live call", field, len(d.Expected)))
		case models.DiffKindMissingInMock:
			parts = append(parts, fmt.Sprintf("%s: live (%d bytes), absent in recording", field, len(d.Actual)))
		case models.DiffKindTypeChanged:
			parts = append(parts, field+": type changed")
		default:
			parts = append(parts, fmt.Sprintf("%s: recorded %d bytes, live %d bytes", field, len(d.Expected), len(d.Actual)))
		}
	}
	return strings.Join(parts, "; ")
}

// LogNextStep is a report's next step as a log line says it: the matcher's
// advice, or the learn step's reason, with every field path it names in its
// shape (models.UnmatchedCall.SanitizedNextStep, the form a proven run's
// evidence keeps), so a map key that may be a value (an e-mail address, a
// user ID) is {}, and a sessionCalls pathPrefix it advises (the call's own
// path, which the report keeps) in the call's shape, as LogCall writes it. The text is keploy's own words: a matcher or a learn step
// writes no value into it (lengths and types instead).
func LogNextStep(r *models.MockMismatchReport) string {
	if r == nil {
		return ""
	}
	return models.UnmatchedCall{NextSteps: r.NextSteps, FieldDiffs: r.FieldDiffs, VariablePlaces: r.VariablePlaces}.SanitizedNextStep()
}
