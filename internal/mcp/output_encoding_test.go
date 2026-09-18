package mcp

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// Valid UTF-8 passes through untouched: no encoding metadata, no base64 copy.
func TestDecodeCommandOutputLeavesUTF8Alone(t *testing.T) {
	out := decodeCommandOutput("组名      类型\r\nEveryone  已知组")
	if out.Text != "组名      类型\r\nEveryone  已知组" {
		t.Errorf("text changed: %q", out.Text)
	}
	if len(out.Meta) != 0 {
		t.Errorf("no metadata expected, got %v", out.Meta)
	}
}

// U+FFFD inside otherwise valid UTF-8 means an upstream stage already decoded
// lossily; that must be surfaced, not passed off as clean output.
func TestDecodeCommandOutputWarnsAboutReplacementRunes(t *testing.T) {
	out := decodeCommandOutput("服务\uFFFD名称")
	if !strings.Contains(out.Text, "服务") {
		t.Errorf("text should stay readable: %q", out.Text)
	}
	if out.Meta["replaced_runes"] != 1 {
		t.Errorf("replaced_runes = %v", out.Meta["replaced_runes"])
	}
	if out.Meta["encoding_warning"] == nil {
		t.Errorf("a warning is expected: %v", out.Meta)
	}
}

// Raw GBK bytes (what a Windows host's code page produces) are decoded instead
// of being destroyed by the JSON encoder, and the original bytes are preserved
// in base64.
func TestDecodeCommandOutputDecodesGBK(t *testing.T) {
	const want = "组信息\r\n组名 类型 必需的组"
	gbk, _, err := transform.Bytes(simplifiedchinese.GBK.NewEncoder(), []byte(want))
	if err != nil {
		t.Fatalf("encode GBK: %v", err)
	}
	if utf8.Valid(gbk) {
		t.Fatalf("test fixture is not raw GBK bytes: % x", gbk)
	}

	out := decodeCommandOutput(string(gbk))
	if out.Text != want {
		t.Errorf("decoded = %q, want %q", out.Text, want)
	}
	if out.Meta["output_encoding"] != "gbk" {
		t.Errorf("output_encoding = %v", out.Meta["output_encoding"])
	}
	wantB64 := base64.StdEncoding.EncodeToString(gbk)
	if out.Meta["output_base64"] != wantB64 {
		t.Errorf("output_base64 = %v, want %v", out.Meta["output_base64"], wantB64)
	}

	// The point of the exercise: the tool result must survive JSON encoding
	// without turning into U+FFFD mojibake.
	encoded, err := json.Marshal(map[string]any{"output": out.Text})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), `\ufffd`) || strings.Contains(string(encoded), "\uFFFD") {
		t.Errorf("JSON encoding replaced bytes: %s", encoded)
	}
	if !strings.Contains(string(encoded), "组信息") {
		t.Errorf("JSON encoding lost the Chinese text: %s", encoded)
	}
}

// Bytes neither valid UTF-8 nor decodable as GBK are handed over as base64
// rather than silently mangled.
func TestDecodeCommandOutputFallsBackToBase64(t *testing.T) {
	raw := string([]byte{0x81, 0x20, 0xFF}) // invalid GBK trail bytes
	out := decodeCommandOutput(raw)
	if out.Meta["output_is_base64"] != true {
		t.Skipf("the GBK decoder accepted the fixture (decoded %q); nothing to assert", out.Text)
	}
	if out.Meta["output_encoding"] != "base64" {
		t.Errorf("output_encoding = %v", out.Meta["output_encoding"])
	}
	decoded, err := base64.StdEncoding.DecodeString(out.Text)
	if err != nil || string(decoded) != raw {
		t.Errorf("base64 output does not round-trip: %q (%v)", out.Text, err)
	}
}
