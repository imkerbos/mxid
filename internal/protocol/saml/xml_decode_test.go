package saml

import (
	"errors"
	"strings"
	"testing"
)

type idHolder struct {
	ID string `xml:"ID,attr"`
}

func TestSafeXMLDecode_RejectsDoctype(t *testing.T) {
	payload := []byte(`<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<AuthnRequest ID="abc"/>`)
	var dst idHolder
	err := safeXMLDecode(payload, &dst)
	if !errors.Is(err, ErrXMLForbiddenDoctype) {
		t.Errorf("expected ErrXMLForbiddenDoctype, got %v", err)
	}
}

func TestSafeXMLDecode_RejectsBillionLaughs(t *testing.T) {
	payload := []byte(`<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;">
]>
<AuthnRequest ID="&lol2;"/>`)
	var dst idHolder
	err := safeXMLDecode(payload, &dst)
	if !errors.Is(err, ErrXMLForbiddenDoctype) {
		t.Errorf("expected DOCTYPE block to fire, got %v", err)
	}
}

func TestSafeXMLDecode_AcceptsCleanXML(t *testing.T) {
	payload := []byte(`<?xml version="1.0"?><AuthnRequest ID="abc-123"/>`)
	var dst idHolder
	if err := safeXMLDecode(payload, &dst); err != nil {
		t.Fatalf("clean XML rejected: %v", err)
	}
	if dst.ID != "abc-123" {
		t.Errorf("ID parse mismatch: %q", dst.ID)
	}
}

func TestSafeXMLDecode_RejectsMalformed(t *testing.T) {
	payload := []byte(`<AuthnRequest`)
	var dst idHolder
	err := safeXMLDecode(payload, &dst)
	if err == nil {
		t.Errorf("malformed XML must error")
	}
	if !strings.Contains(err.Error(), "saml xml") {
		t.Errorf("error must be prefixed with package context, got %v", err)
	}
}

func TestContainsDoctype_CaseInsensitive(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"<!DOCTYPE foo>", true},
		{"<!doctype foo>", true},
		{"<!DocType foo>", true},
		{"<AuthnRequest/>", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := containsDoctype([]byte(tc.in)); got != tc.want {
			t.Errorf("containsDoctype(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
