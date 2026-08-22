package zkaudit

import "strings"

const RedactedValue = "[REDACTED]"

var sensitiveHeaderNames = map[string]bool{
	"cookie":              true,
	"set-cookie":          true,
	"authorization":       true,
	"proxy-authorization": true,
	"x-api-key":           true,
	"x-auth-token":        true,
	"x-csrf-token":        true,
	"x-session-token":     true,
}

func isSensitiveHeader(name string) bool {
	return sensitiveHeaderNames[strings.ToLower(name)]
}

func redactHeaders(hs []Header) []Header {
	out := make([]Header, len(hs))
	for i, h := range hs {
		if isSensitiveHeader(h.Name) {
			out[i] = Header{Name: h.Name, Value: RedactedValue}
		} else {
			out[i] = h
		}
	}
	return out
}

func redactCookies(cs []Cookie) []Cookie {
	out := make([]Cookie, len(cs))
	for i, c := range cs {
		out[i] = Cookie{Name: c.Name, Value: RedactedValue}
	}
	return out
}

func Redact(h *HAR) *HAR {
	out := &HAR{}
	out.Log.Entries = make([]Entry, len(h.Log.Entries))
	for i, e := range h.Log.Entries {
		e.Request.Headers = redactHeaders(e.Request.Headers)
		e.Request.Cookies = redactCookies(e.Request.Cookies)
		e.Response.Headers = redactHeaders(e.Response.Headers)
		e.Response.Cookies = redactCookies(e.Response.Cookies)
		out.Log.Entries[i] = e
	}
	return out
}
