package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The agent's capture paths never log what they capture: a request or
// response body, a payload, a frame, a header's value. Those are the
// customer's content, and logs leave the cluster (an unreadable request body
// was logged whole, as base64, at Warn). This gate reads the capture paths'
// source and fails on a log line that takes one.
//
// It is a tripwire on names and shapes, not a proof: it cannot see types, and
// it does not look inside a helper a log line calls (matchSignature(frame) is
// that helper's business). What it catches:
//   - a bytes field: zap.Binary, zap.ByteString, zap.ByteStrings (but for one
//     keyed as a process of keploy's own output: a keytool run's, a stack);
//   - bytes encoded into a log line: base64 or hex EncodeToString, hex.Dump;
//   - a field keyed as a body, payload, buffer, header or authorization (a
//     "cookie" here is a socket's, so a Cookie header is caught as a header),
//     or as a dump of bytes (hex, base64, dump);
//   - a field or message made from a value named as a body, payload, buffer,
//     frame, chunk, packet, header, request, response, query, data or
//     statement (an err-named value too, when its name says content)
//     (through string(x), []byte(x), x.String(),
//     fmt.Sprint*, the strings and bytes packages, concatenation, slicing);
//   - a header's value read into one (Get or Values on a value named as a
//     header set, of any header but the few that only frame the body or say
//     where it came from);
//   - a URL whole (a value named URL, URI or RawQuery): its query values
//     are content. What a log says of a request is utils.GetReqMeta's
//     method, host, path shape and query parameter names;
//   - a URL's path whole (u.Path, u.RawPath, u.EscapedPath() of a value
//     named URL or URI): a segment may hold a value (an ID, an e-mail
//     address), so a log names a path by its shape (models.PathShape);
//   - a query or form value read into one (Query().Get, FormValue,
//     PostFormValue, Form.Get, PostForm.Get);
//   - a call's path held whole under a name for one (reqPath, mockPath,
//     urlPath), for the same reason;
//   - a mock-mismatch report's values (its ActualSummary, ExpectedSummary,
//     Diff, FieldDiffs, NextSteps): a log names the call, how it differs and
//     what to do by mismatch.LogCall, LogDiff and LogNextStep;
//   - any of these as a field of a struct literal a log line takes, as what
//     a function literal called in place returns, as zap.Inline's value, or
//     built into a local text or list first (append, fmt.Sprint*,
//     strings.Join, +, +=) that a log line then takes;
//   - a parsed query or form whole (r.URL.Query(), its Encode, r.Form,
//     r.PostForm), a URL's Redacted form, a Referer.
//
// Limits, stated: a value is followed one hop, through a local text or list
// only (a value passed through a struct field, a map or a helper is not);
// a name says what a value holds (a captured byte slice named m or s, or a
// header set named other than h or *header(s), passes); an error's text is
// its maker's.
//
// A length (len(body)), a number, a flag or an instant is never content. An
// error (zap.Error, fmt.Errorf) is out of its reach: what an error says is
// its maker's business. http.Error writes the agent API's own reply, not a
// log line.
var capturePathDirs = []string{"pkg/service/agent", "pkg/agent", "pkg/core/proxy"}

var (
	// contentKeyRe: a field key that says the field is content.
	contentKeyRe = regexp.MustCompile(`(?i)^((req|request|resp|response|http|raw|mock|reply)?[ _-]?(body|bodies|payload|buf|buffer|headers?|authorization)|hex|hex[ _-]?dump|dump|base64|b64|\w+[ _-](hex|base64|b64))$`)
	// contentNameRe: the last name of a value that holds content.
	contentNameRe = regexp.MustCompile(`(?i)(body|bodies|payload|buf|buffer|frame|chunk|packet|headers?|req|request|resp|response|query|^data|stmt)(str|string|bytes)?$`)
	// headerSetRe: the name of a value that holds a request's or a
	// response's headers (Header, header, reqHeaders, h).
	headerSetRe = regexp.MustCompile(`(?i)(^h$|headers?$)`)
	// urlNameRe: the last name of a value that holds a URL whole, query
	// values and all.
	urlNameRe = regexp.MustCompile(`(?i)(url|uri|rawquery)$`)
	// callPathNameRe: the last name of a value that holds a call's path
	// whole (reqPath, mockPath, urlPath), whose segments may hold values. A
	// path of keploy's own (a file's, a socket's) is named otherwise.
	callPathNameRe = regexp.MustCompile(`(?i)(req|request|mock|url|uri)_?path$`)
	// reportValueFields are the fields of a mock-mismatch report that hold
	// the call's values (models.MockMismatchReport): what the call was, how
	// it differs, field by field, and the next step, whose field paths may
	// hold a map key that is a value. The report keeps them; a log line names
	// the call, its differences and its next step by mismatch.LogCall,
	// LogDiff and LogNextStep.
	reportValueFields = map[string]bool{"ActualSummary": true, "ExpectedSummary": true, "Diff": true, "FieldDiffs": true, "NextSteps": true}
	// logMethods are the methods that write a log line, on any receiver.
	logMethods = map[string]bool{}
	// framingHeaders say how a body is framed, not what it holds, or where a
	// request came from: an Origin and a Host are a scheme, a host and a
	// port, never a path, a query or a credential.
	framingHeaders = map[string]bool{
		"content-type": true, "content-encoding": true, "content-length": true,
		"transfer-encoding": true, "expect": true, "upgrade": true, "connection": true,
		"origin": true, "host": true,
	}
	// processOutputKeys key the bytes a process of keploy's own wrote: a
	// keytool or certutil run's output, a panic's stack. They are not
	// captured, so a bytes field may hold them; what it holds is still
	// checked.
	processOutputKeys = map[string]bool{"output": true, "certutil": true, "stack": true, "stderr": true, "stdout": true}
	// configNames are values a name rule would catch that are the user's own
	// keploy config, not captured: an async lane's query match.
	configNames = map[string]bool{"MatchQuery": true}
	// ownAPIFiles log a request to the agent's own API by its path, not a
	// captured call: a keploy route, or the one a refused request probed,
	// which its refusal is logged to show.
	ownAPIFiles = map[string]bool{filepath.Join("pkg", "agent", "routes", "auth.go"): true}
)

// pathWhole starts the reason a URL's path whole is caught for.
const pathWhole = "a URL's path whole"

func init() {
	for _, level := range []string{"Debug", "Info", "Warn", "Error", "DPanic", "Panic", "Fatal", "Print"} {
		for _, suffix := range []string{"", "f", "w", "ln"} {
			logMethods[level+suffix] = true
		}
	}
}

// contentLog is one log line that takes captured content.
type contentLog struct {
	pos token.Position
	why string
}

// contentLogsIn returns the log lines of f that take captured content.
func contentLogsIn(fset *token.FileSet, f *ast.File) []contentLog {
	zapName, utilsName := "", ""
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		name := filepath.Base(path)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		switch path {
		case "go.uber.org/zap":
			zapName = name
		case "go.keploy.io/server/v3/utils":
			utilsName = name
		}
	}
	var found []contentLog
	c := &checker{assigns: localAssigns(f), following: map[*ast.Object]bool{}, flag: func(n ast.Node, why string) {
		found = append(found, contentLog{fset.Position(n.Pos()), why})
	}}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, _ := sel.X.(*ast.Ident)
		switch {
		case zapName != "" && pkg != nil && pkg.Name == zapName:
			checkZapField(call, sel.Sel.Name, c)
		case utilsName != "" && pkg != nil && pkg.Name == utilsName && sel.Sel.Name == "LogError":
			// LogError(logger, err, msg, fields...): msg is the line.
			for _, a := range call.Args[min(2, len(call.Args)):] {
				checkValue(a, c)
			}
		case logMethods[sel.Sel.Name] && !notALogLine(sel):
			for _, a := range call.Args {
				checkValue(a, c)
			}
		}
		return true
	})
	return found
}

// notALogLine: fmt.Errorf builds an error and http.Error writes a reply to
// the agent's own API client; neither writes a log line.
func notALogLine(sel *ast.SelectorExpr) bool {
	pkg, ok := sel.X.(*ast.Ident)
	return ok && (pkg.Name == "fmt" && sel.Sel.Name == "Errorf" || pkg.Name == "http" && sel.Sel.Name == "Error")
}

// checker carries what a check reads across a file: where a log line
// reports, and what each local name of the file is assigned.
type checker struct {
	flag func(ast.Node, string)
	// assigns are the values each local name is assigned (localAssigns), and
	// following the names whose values are being checked, so a name a line
	// takes is checked by what it was given too: a list built by append, a
	// text built by fmt.Sprintf.
	assigns   map[*ast.Object][]ast.Expr
	following map[*ast.Object]bool
}

// localAssigns maps each name f declares to every text or list f builds
// into it (builds): the one hop the gate follows. A name given a value any
// other way (host = req.RequestURI for a CONNECT) is checked by its own
// name only, as before.
func localAssigns(f *ast.File) map[*ast.Object][]ast.Expr {
	out := map[*ast.Object][]ast.Expr{}
	add := func(id *ast.Ident, v ast.Expr, appended bool) {
		if id.Obj != nil && (appended || builds(v)) {
			out[id.Obj] = append(out[id.Obj], v)
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Rhs) != len(x.Lhs) {
				return true
			}
			for i, lhs := range x.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					add(id, x.Rhs[i], x.Tok == token.ADD_ASSIGN)
				}
			}
		case *ast.ValueSpec:
			for i, id := range x.Names {
				if i < len(x.Values) {
					add(id, x.Values[i], false)
				}
			}
		}
		return true
	})
	return out
}

// builds reports whether v builds a text or a list from its parts: an
// append, a fmt.Sprint*, a strings.Join, a concatenation.
func builds(v ast.Expr) bool {
	switch x := v.(type) {
	case *ast.BinaryExpr:
		return x.Op == token.ADD
	case *ast.CallExpr:
		switch fn := x.Fun.(type) {
		case *ast.Ident:
			return fn.Name == "append"
		case *ast.SelectorExpr:
			pkg, ok := fn.X.(*ast.Ident)
			return ok && (pkg.Name == "fmt" && strings.HasPrefix(fn.Sel.Name, "Sprint") || pkg.Name == "strings" && fn.Sel.Name == "Join")
		}
	}
	return false
}

// checkZapField flags a zap field constructor call that takes content.
func checkZapField(call *ast.CallExpr, ctor string, c *checker) {
	switch ctor {
	case "Binary", "ByteString", "ByteStrings":
		if len(call.Args) == 2 && processOutputKeys[literalKey(call.Args[0])] {
			checkValue(call.Args[1], c)
			return
		}
		c.flag(call, "a bytes field (zap."+ctor+")")
		return
	case "Error", "NamedError", "Errors", "Skip", "Namespace":
		return
	}
	for _, scalar := range []string{"Int", "Uint", "Float", "Complex", "Bool", "Duration", "Time", "Uintptr"} {
		if strings.HasPrefix(ctor, scalar) {
			return // a number, a flag or an instant holds no content
		}
	}
	if len(call.Args) == 0 {
		return
	}
	if ctor == "Inline" {
		// Inline(v): v's fields are the line's own.
		checkValue(call.Args[0], c)
		return
	}
	if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
		if key, err := strconv.Unquote(lit.Value); err == nil && contentKeyRe.MatchString(key) {
			c.flag(call, "a field keyed as content ("+strconv.Quote(key)+")")
		}
	}
	for _, a := range call.Args[1:] {
		checkValue(a, c)
	}
}

// literalKey is a field key written as a string literal, "" for any other.
func literalKey(e ast.Expr) string {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	key, _ := strconv.Unquote(lit.Value)
	return key
}

// checkValue flags content flowing into a log field or message through e.
func checkValue(e ast.Expr, c *checker) {
	switch x := e.(type) {
	case *ast.Ident:
		checkName(x, x.Name, c)
		if x.Obj != nil && !c.following[x.Obj] {
			c.following[x.Obj] = true
			for _, v := range c.assigns[x.Obj] {
				checkValue(v, c)
			}
			delete(c.following, x.Obj)
		}
	case *ast.SelectorExpr:
		checkName(x, x.Sel.Name, c)
	case *ast.ParenExpr:
		checkValue(x.X, c)
	case *ast.StarExpr:
		checkValue(x.X, c)
	case *ast.UnaryExpr:
		checkValue(x.X, c)
	case *ast.BinaryExpr:
		checkValue(x.X, c)
		checkValue(x.Y, c)
	case *ast.IndexExpr:
		checkValue(x.X, c)
	case *ast.SliceExpr:
		checkValue(x.X, c)
	case *ast.TypeAssertExpr:
		checkValue(x.X, c)
	case *ast.CallExpr:
		checkCall(x, c)
	case *ast.CompositeLit:
		// A struct, slice or map literal: whatever its elements hold, the
		// line takes.
		for _, el := range x.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				checkValue(kv.Key, c)
				checkValue(kv.Value, c)
				continue
			}
			checkValue(el, c)
		}
	case *ast.KeyValueExpr:
		checkValue(x.Value, c)
	}
}

// checkCall follows a call that passes its arguments' content on (a
// conversion, a formatter, a strings or bytes function, x.String()) and flags
// one that encodes bytes, or a helper whose name says it returns a URL whole
// (upstreamRequestURL). A count (len, cap) holds no content, and any other
// call is a helper this gate does not look into.
func checkCall(call *ast.CallExpr, c *checker) {
	switch fn := call.Fun.(type) {
	case *ast.FuncLit:
		// A function literal called in place: what it returns, the line
		// takes.
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if _, ok := n.(*ast.FuncLit); ok {
				return false
			}
			if ret, ok := n.(*ast.ReturnStmt); ok {
				for _, r := range ret.Results {
					checkValue(r, c)
				}
			}
			return true
		})
	case *ast.Ident:
		switch fn.Name {
		case "len", "cap":
			return
		case "append":
			for _, a := range call.Args[min(1, len(call.Args)):] {
				checkValue(a, c)
			}
			return
		case "string":
			for _, a := range call.Args {
				checkValue(a, c)
			}
			return
		}
		if cutsContent(fn.Name) {
			for _, a := range call.Args {
				checkValue(a, c)
			}
			return
		}
		checkHelperName(call, fn.Name, c)
	case *ast.ArrayType: // []byte(x)
		for _, a := range call.Args {
			checkValue(a, c)
		}
	case *ast.SelectorExpr:
		name := fn.Sel.Name
		if name == "EncodeToString" || name == "Dump" {
			c.flag(call, "bytes encoded into a log line ("+name+")")
			return
		}
		if pkg, ok := fn.X.(*ast.Ident); ok {
			switch pkg.Name {
			case "fmt", "strings", "bytes":
				for _, a := range call.Args {
					checkValue(a, c)
				}
				return
			}
		}
		if (name == "String" || name == "Bytes") && len(call.Args) == 0 {
			checkValue(fn.X, c)
			return
		}
		if cutsContent(name) {
			for _, a := range call.Args {
				checkValue(a, c)
			}
			return
		}
		checkHelperName(call, name, c)
		switch {
		case (name == "Query" || name == "Redacted") && len(call.Args) == 0 && namesAURL(fn.X):
			c.flag(call, "a URL's query values ("+name+")")
		case name == "Encode" && isQueryOrForm(fn.X):
			c.flag(call, "a query or form's values (Encode)")
		case name == "Referer" && len(call.Args) == 0:
			c.flag(call, "a header's value (Referer)")
		case name == "EscapedPath" && namesAURL(fn.X):
			c.flag(call, pathWhole+": a segment may hold a value (EscapedPath)")
		case name == "FormValue" || name == "PostFormValue":
			c.flag(call, "a form value ("+name+")")
		case name == "Get" && isQueryOrForm(fn.X):
			c.flag(call, "a query or form value")
		}
		if name == "Get" || name == "Values" {
			if namesAHeader(fn.X) && len(call.Args) == 1 {
				var h string
				if lit, ok := call.Args[0].(*ast.BasicLit); ok {
					h, _ = strconv.Unquote(lit.Value)
				}
				if !framingHeaders[strings.ToLower(h)] {
					c.flag(call, "a header's value")
				}
			}
		}
	}
}

// namesAURL reports whether e is a value named as a URL (urlNameRe): r.URL,
// input.url, u.URI.
func namesAURL(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return urlNameRe.MatchString(x.Name)
	case *ast.SelectorExpr:
		return urlNameRe.MatchString(x.Sel.Name)
	}
	return false
}

// namesAHeader reports whether e is a value named as a header set
// (r.Header, input.header, h := r.Header), whose Get reads a value.
func namesAHeader(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return headerSetRe.MatchString(x.Name)
	case *ast.SelectorExpr:
		return headerSetRe.MatchString(x.Sel.Name)
	}
	return false
}

// isQueryOrForm reports whether e is a URL's parsed query (r.URL.Query()) or
// a request's parsed form (r.Form, r.PostForm), whose Get reads a value.
func isQueryOrForm(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.CallExpr:
		sel, ok := x.Fun.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "Query" && len(x.Args) == 0
	case *ast.SelectorExpr:
		return x.Sel.Name == "Form" || x.Sel.Name == "PostForm"
	}
	return false
}

// cutsContent reports whether a helper is named for cutting what it is given
// (truncate, truncateValue, utils.TruncateString): what it returns is a
// stretch of its argument, so its arguments are checked as the line's own.
func cutsContent(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "trunc")
}

// checkHelperName flags a call to a helper named for the URL it returns: its
// result is a URL whole, query values and all, whatever it is given.
func checkHelperName(call *ast.CallExpr, name string, c *checker) {
	if urlNameRe.MatchString(name) {
		c.flag(call, "a URL whole, from a helper named for it ("+name+")")
	}
}

func checkName(n ast.Node, name string, c *checker) {
	if configNames[name] {
		return
	}
	if sel, ok := n.(*ast.SelectorExpr); ok && (name == "Path" || name == "RawPath") && namesAURL(sel.X) {
		c.flag(n, pathWhole+": a segment may hold a value ("+name+")")
		return
	}
	if _, ok := n.(*ast.SelectorExpr); ok && (name == "Form" || name == "PostForm") {
		c.flag(n, "a request's form values ("+name+")")
		return
	}
	if (strings.HasPrefix(name, "Err") || strings.HasPrefix(name, "err")) && !contentNameRe.MatchString(name) {
		return // an error value: its text is the error's
	}
	if _, ok := n.(*ast.SelectorExpr); ok && reportValueFields[name] {
		c.flag(n, "a mismatch report's values ("+name+"): log it by mismatch.LogCall, LogDiff or LogNextStep")
		return
	}
	if callPathNameRe.MatchString(name) {
		c.flag(n, pathWhole+": a segment may hold a value ("+name+")")
		return
	}
	if contentNameRe.MatchString(name) {
		c.flag(n, "a value named as content ("+name+")")
	}
	if urlNameRe.MatchString(name) {
		c.flag(n, "a URL whole, query values and all ("+name+")")
	}
}

func TestCapturePathsLogNoContent(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	fset := token.NewFileSet()
	files := 0
	for _, dir := range capturePathDirs {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			files++
			for _, c := range contentLogsIn(fset, f) {
				rel, _ := filepath.Rel(root, c.pos.Filename)
				if ownAPIFiles[rel] && strings.HasPrefix(c.why, pathWhole) {
					continue
				}
				t.Errorf("%s:%d: a log line takes captured content: %s", rel, c.pos.Line, c.why)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// The walk must have read the capture paths, not an empty or moved tree.
	if files < 200 {
		t.Fatalf("read only %d source files under %v; the capture paths moved?", files, capturePathDirs)
	}
}

// TestCapturePathsLogNoContentCatches: each shape the gate exists for is
// caught, each that holds no content is not. The first is the line this gate
// was written for.
func TestCapturePathsLogNoContentCatches(t *testing.T) {
	const header = "package p\nimport (\n\"go.uber.org/zap\"\n\"go.keploy.io/server/v3/utils\"\n)\nfunc f() {\n"
	for _, c := range []struct {
		src    string
		caught bool
	}{
		{`logger.Warn("failed to read the http request body", zap.Int64("of size", int64(len(reqBody))), zap.String("body", base64.StdEncoding.EncodeToString(reqBody)), zap.Error(err))`, true},
		{`logger.Warn("x", zap.String("b64", base64.StdEncoding.EncodeToString(reqBody)))`, true},
		{`logger.Debug("x", zap.String("prefix", hex.EncodeToString(x)))`, true},
		{`logger.Debug("x", zap.ByteString("message", m))`, true},
		{`logger.Debug("x", zap.Binary("m", m))`, true},
		{`logger.Debug(fmt.Sprintf("This is the complete request:\n%v", string(reqBuf)))`, true},
		{`logger.Debug("This was the last response:\n" + string(responseBody))`, true},
		{`logger.Debugf("got %s", body)`, true},
		{`logger.Debug("x", zap.String("payload", s))`, true},
		{`logger.Debug("x", zap.String("response_body", s))`, true},
		{`fields = append(fields, zap.String("s", string(req.Body)))`, true},
		{`logger.Debug("x", zap.Any("h", req.Header))`, true},
		{`logger.Debug("x", zap.String("auth", req.Header.Get("Authorization")))`, true},
		{`logger.Debug("x", zap.String("b", compressedBuffer.String()))`, true},
		{`logger.Debug("x", zap.String("b", strings.TrimSpace(string(respBody[:n]))))`, true},
		{`utils.LogError(logger, err, "failed: "+string(buf))`, true},
		{`ce.Write(zap.String("f", string(reqFrame)))`, true},
		{`logger.Error("x", zap.String("url", req.URL.String()), zap.String("method", req.Method))`, true},
		{`logger.Debug("x", zap.String("url", tc.HTTPReq.URL))`, true},
		{`logger.Info("x", zap.String("from", origURL))`, true},
		{`logger.Debug("x", zap.String("u", r.RequestURI), zap.String("q", r.URL.RawQuery))`, true},
		{`logger.Debug("TLS-detect: first chunk hex", zap.Int("dataLen", len(data)), zap.String("hex", fmt.Sprintf("%x", head)))`, true},
		{`h.Logger.Debug(fmt.Sprintf("This is the complete request:\n%v", string(finalReq)))`, true},
		{`h.Logger.Debug("This is the final response: " + string(finalResp))`, true},
		{`logger.Debug("Matched the command with the mock", zap.Any("mock", resp))`, true},
		{`logger.Info("x", zap.String("query", strings.TrimSpace(sp.Query)))`, true},
		{`logger.Debug("x", zap.ByteString("output", reqBody))`, true},
		{`logger.Debug("x", zap.ByteString("err", buf[4:]))`, true},
		{`logger.Debug("x", zap.Any("headers", string(initialBuf)))`, true},
		{`logger.Warn("x", zap.String("auth", r.Header.Get("Cookie")))`, true},
		{`h.Logger.Error("x", zap.String("upstream_url", upstreamRequestURL(finalReq, destConn.RemoteAddr())))`, true},
		{`logger.Info("x", zap.String("to", util.RequestURL(r)))`, true},
		{`logger.Info("x", zap.String("to", r.URL.RequestURI()))`, true},
		{`logger.Error("x", zap.String("sql_query", truncate(actualQuery, 300)))`, true},
		{`logger.Debug("x", zap.String("v", utils.TruncateString(string(body), 64)))`, true},
		{`logger.Error("x", zap.Stringer("sql_query", sqlCut{actualQuery, 300}))`, true},
		{`logger.Debug("x", zap.Any("m", map[string]string{"path": "p", "b": string(reqBody)}))`, true},
		{`logger.Debug("x", zap.Any("m", meta{Name: n, Body: b}))`, true},
		{`logger.Debug("x", zap.Any("m", []string{r.URL.RawQuery}))`, true},
		{`logger.Debug("x", zap.String("token", r.URL.Query().Get("token")))`, true},
		{`logger.Debug("x", zap.String("e", r.FormValue("email")))`, true},
		{`logger.Debug("x", zap.String("p", r.PostFormValue("pw")))`, true},
		{`logger.Debug("x", zap.String("e", r.Form.Get("email")))`, true},
		{`logger.Debug("x", zap.String("e", r.PostForm.Get("email")))`, true},
		{`logger.Debug("x", zap.String("path", r.URL.Path))`, true},
		{`logger.Debug("x", zap.String("path", input.url.RawPath))`, true},
		{`logger.Debug("x", zap.String("path", req.URL.EscapedPath()))`, true},
		{`ce.Write(zap.Any("parsed URL", mockPath), zap.Any("req path", reqPath))`, true},
		{`logger.Debug("x", zap.String("final_response_hex", fmt.Sprintf("%x", resultSet.FinalResponse.Data)))`, true},
		{`logger.Debug("x", zap.String("packet b64", enc(pkt.Data)))`, true},
		{`logger.Debug("x", zap.String("p", urlPath))`, true},
		{`h.Logger.Debug("no matching http mock found", zap.String("diff", report.Diff))`, true},
		{`p.logger.Warn("x", zap.String("actual", r.ActualSummary), zap.String("expected", r.ExpectedSummary))`, true},
		{`logger.Debug("x", zap.Any("fields", report.FieldDiffs))`, true},
		{`p.logger.Warn("x", zap.String("next_step", r.NextSteps))`, true},
		{"var all []string\nfor _, e := range es {\nall = append(all, fmt.Sprintf(\"query=%q\", e.query))\n}\nlogger.Debug(\"x\", zap.String(\"entries\", strings.Join(all, \" | \")))", true},
		{"msg := \"got \" + string(b)\nmsg += string(body)\nlogger.Debug(msg)", true},
		{`logger.Debug("x", zap.String("auth", input.header.Get("Authorization")))`, true},
		{"h := r.Header\nlogger.Debug(\"x\", zap.String(\"a\", h.Get(\"Authorization\")))", true},
		{`logger.Debug("x", zap.Any("q", r.URL.Query()))`, true},
		{`logger.Debug("x", zap.String("q", u.Query().Encode()))`, true},
		{`logger.Debug("x", zap.String("u", r.URL.Redacted()))`, true},
		{`logger.Debug("x", zap.String("ref", r.Referer()))`, true},
		{`logger.Debug("x", zap.Any("f", r.Form))`, true},
		{`logger.Debug("x", zap.Any("p", r.PostForm))`, true},
		{`logger.Debug("x", zap.String("e", errBody))`, true},
		{`logger.Debug("x", zap.String("q", func() string { return query }()))`, true},
		{`logger.Debug("x", zap.Inline(req))`, true},
		{`logger.Debug("x", zap.String("d", string(data)), zap.String("s", stmt))`, true},

		{`logger.Warn("failed to read the http request body", zap.Int("bytesRead", len(reqBody)), zap.String("contentType", req.Header.Get("Content-Type")), zap.Error(err))`, false},
		{`logger.Debug("x", zap.Int64("body_size_bytes", n), zap.Int("reqBodySize", len(reqBody)))`, false},
		{`logger.Debug("x", zap.Uint8("contentType", data[0]), zap.String("mock", stub.Name))`, false},
		{`logger.Debug("x", zap.Error(ErrShortBody), zap.String("bodyType", req.BodyType))`, false},
		{`utils.LogError(logger, err, "failed to read the body")`, false},
		{`logger.Debug("x", zap.String("signature", matchSignature(frame)))`, false},
		{`return fmt.Errorf("short body: %w", err)`, false},
		{`logger.Debug("x", zap.Int("frameBytes", payloadBytes), zap.Uint64("cookie", cookie))`, false},
		{`logger.Error("x", zap.Any("metadata", utils.GetReqMeta(req)), zap.String("path", models.PathShape(req.URL.EscapedPath())))`, false},
		{`logger.Debug("x", zap.Any("metadata", testCaseMeta(tc)), zap.Bool("handshakeRecord", data[0] == 0x16))`, false},
		{`http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)`, false},
		{`logger.Debug("x", zap.String("alias", alias), zap.ByteString("output", out), zap.Error(err))`, false},
		{`s.cfg.Logger.Error("parser panicked", zap.Any("panic", panicVal), zap.ByteString("stack", stack))`, false},
		{`logger.Warn("x", zap.String("path", models.PathShape(r.URL.Path)), zap.String("origin", r.Header.Get("Origin")))`, false},
		{`ce.Write(zap.String("parsed URL", models.PathShape(mockPath)), zap.String("req path", models.PathShape(reqPath)))`, false},
		{`logger.Debug("x", zap.String("actual", mismatch.LogCall(report)), zap.String("diff", mismatch.LogDiff(report)), zap.String("cert", certPath))`, false},
		{`p.logger.Warn("x", zap.String("next_step", mismatch.LogNextStep(r)), zap.String("closest", r.ClosestMock))`, false},
		{`logger.Debug("x", zap.String("method", grpcMethod(http2Stream)), zap.String("query", models.SQLShape(sp.Query)))`, false},
		{`h.Logger.Debug("read the complete request", zap.Int("bytes", len(finalReq)))`, false},
		{`logger.Error("x", zap.Stringer("sql_query", sqlShape(actualQuery)), zap.String("mock", truncate(mock.Name, 64)))`, false},
		{`logger.Debug("x", zap.Any("sizes", struct{ N, M int }{len(body), len(resp.Body)}), zap.Any("m", map[string]string{"mock": m.Name}))`, false},
		{`h.Logger.Info("x", zap.Any("upstream", upstreamRequestMeta(finalReq, destConn.RemoteAddr())), zap.String("u", strconv.Itoa(len(u.URL))))`, false},
		{"var all []string\nfor _, e := range es {\nall = append(all, fmt.Sprintf(\"query=%q\", models.SQLShape(e.query)))\n}\nlogger.Debug(\"x\", zap.String(\"entries\", strings.Join(all, \" | \")))", false},
		{"target := req.Host\nif target == \"\" {\ntarget = req.RequestURI\n}\nlogger.Debug(\"x\", zap.String(\"target\", target))", false},
		{`logger.Debug("x", zap.String("ct", input.header.Get("Content-Type")), zap.String("host", r.URL.Hostname()), zap.Int("n", len(data)))`, false},
		{`fmt.Printf("got %s\n", body)`, true},
	} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "p.go", header+c.src+"\n}\n", 0)
		if err != nil {
			t.Fatalf("%s: %v", c.src, err)
		}
		if got := len(contentLogsIn(fset, f)) > 0; got != c.caught {
			t.Errorf("caught=%v, want %v: %s", got, c.caught, c.src)
		}
	}
}
