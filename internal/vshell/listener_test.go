package vshell

import (
	"context"
	"strings"
	"testing"
)

// The console's listener module calls these four endpoints with exactly these
// payloads; the client must match them.
func TestListenerLifecycleRequests(t *testing.T) {
	cases := []struct {
		name    string
		call    func(*Client) error
		wantURL string
		want    map[string]any
	}{
		{
			name:    "start",
			call:    func(c *Client) error { return c.SetListenerStatus(context.Background(), 7, true) },
			wantURL: "/api/listener/start",
			want:    map[string]any{"id": float64(7)},
		},
		{
			name:    "stop",
			call:    func(c *Client) error { return c.SetListenerStatus(context.Background(), 7, false) },
			wantURL: "/api/listener/stop",
			want:    map[string]any{"id": float64(7)},
		},
		{
			name: "editremark",
			call: func(c *Client) error {
				return c.SetListenerRemark(context.Background(), 7, "生产隧道")
			},
			wantURL: "/api/listener/editremark",
			want:    map[string]any{"id": float64(7), "remark": "生产隧道"},
		},
	}
	for _, tc := range cases {
		stub := newAPIStub(t, tc.wantURL, `{"code":0,"message":"ok","result":null}`)
		if err := tc.call(stub.client()); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if stub.gotPath != tc.wantURL {
			t.Errorf("%s: path = %q, want %q", tc.name, stub.gotPath, tc.wantURL)
		}
		for k, v := range tc.want {
			if got := stub.gotBody[k]; got != v {
				t.Errorf("%s: body[%q] = %v, want %v (body=%v)", tc.name, k, got, v, stub.gotBody)
			}
		}
	}
}

// edit posts the add payload plus the capital-I Id the server expects.
func TestEditListenerRequest(t *testing.T) {
	stub := newAPIStub(t, "/api/listener/edit", `{"code":0,"message":"ok","result":null}`)
	err := stub.client().EditListener(context.Background(), 9, AddListenerRequest{
		Mode:        "ws",
		ListenAddr:  "0.0.0.0:21480",
		Vkey:        "v",
		EncryptSalt: "s",
	})
	if err != nil {
		t.Fatalf("EditListener: %v", err)
	}
	if stub.gotPath != "/api/listener/edit" {
		t.Errorf("path = %q", stub.gotPath)
	}
	if stub.gotBody["Id"] != float64(9) {
		t.Errorf("edit payload must carry Id, got %v", stub.gotBody)
	}
	if stub.gotBody["Mode"] != "ws" || stub.gotBody["ListenAddr"] != "0.0.0.0:21480" {
		t.Errorf("body = %v", stub.gotBody)
	}
	// Defaults identical to add, so an edit that omits them does not zero them.
	if stub.gotBody["DisconnectTimeout"] != float64(30) || stub.gotBody["PingInterval"] != float64(10) {
		t.Errorf("edit should apply the add defaults, got %v", stub.gotBody)
	}
}

func TestListenerLifecyclePropagatesAPIError(t *testing.T) {
	stub := newAPIStub(t, "/api/listener/start", `{"code":-1,"message":"not found","result":null,"type":"error"}`)
	err := stub.client().SetListenerStatus(context.Background(), 999, true)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %v, want the server message", err)
	}
}
