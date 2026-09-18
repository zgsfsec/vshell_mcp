package mcp

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// decodedOutput is command output that is safe to embed in a JSON tool result,
// plus whatever the caller should know about how it was obtained.
type decodedOutput struct {
	Text string
	Meta map[string]any
}

// decodeCommandOutput prepares shell output for a JSON tool result.
//
// Go's JSON encoder replaces every byte that is not valid UTF-8 with U+FFFD, so
// an undecodable byte stream would otherwise reach the model as silent mojibake:
// the tool would look successful while the Chinese text was destroyed. v_shell's
// terminal currently relays UTF-8 (its client converts from the target's code
// page), but that is a property of *its* build, not a guarantee of this
// protocol — so an undecodable stream is decoded explicitly here (GBK is the
// common case on Windows) and a lossless base64 copy is always attached.
func decodeCommandOutput(s string) decodedOutput {
	if utf8.ValidString(s) {
		if n := strings.Count(s, "\uFFFD"); n > 0 {
			// Valid UTF-8 that already contains replacement characters: some
			// earlier stage decoded lossily, so the original bytes are gone.
			return decodedOutput{Text: s, Meta: map[string]any{
				"replaced_runes": n,
				"encoding_warning": fmt.Sprintf(
					"输出里有 %d 个 U+FFFD 替换字符:说明上游(目标机 agent / 服务端)已按 UTF-8 做过一次有损解码,"+
						"原始字节不可恢复。请让目标程序用 UTF-8 输出(如 Windows 上先执行 chcp 65001),"+
						"或改用 read_file/download_file 走二进制通道取原始内容。", n),
			}}
		}
		return decodedOutput{Text: s}
	}

	raw := []byte(s)
	b64 := base64.StdEncoding.EncodeToString(raw)

	// GBK (CP936) is the overwhelmingly common code page on Chinese Windows and
	// decodes any byte sequence, so only accept it when the result is valid
	// UTF-8 without replacement characters.
	if decoded, _, err := transform.Bytes(simplifiedchinese.GBK.NewDecoder(), raw); err == nil && utf8.Valid(decoded) {
		text := string(decoded)
		if !strings.ContainsRune(text, '\uFFFD') {
			return decodedOutput{Text: text, Meta: map[string]any{
				"output_encoding": "gbk",
				"output_base64":   b64,
				"encoding_note": "输出不是合法 UTF-8,已按 GBK(CP936) 解码为 UTF-8;" +
					"output_base64 是未经改动的原始字节(如需自行解码)。建议让目标用 chcp 65001 + UTF-8 输出以避免歧义。",
			}}
		}
	}

	return decodedOutput{Text: b64, Meta: map[string]any{
		"output_encoding":  "base64",
		"output_is_base64": true,
		"encoding_note": "输出既不是合法 UTF-8,也无法按 GBK 解码,因此 output 字段放的是原始字节的 base64" +
			"(解码后即是命令的原样输出)。请按目标代码页自行解码,或让目标改用 UTF-8 输出。",
	}}
}
