package edge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

// This is a wire-level CDP fixture, not a mock of Session.Close. It exercises
// the real pinned chromedp implementation including its cancellation goroutines.
type targetFixture struct {
	mu          sync.Mutex
	methods     []string
	attached    []string
	disconnects chan struct{}
	failAttach  bool
}

func (f *targetFixture) serve(w http.ResponseWriter, r *http.Request) {
	conn, _, _, err := ws.UpgradeHTTP(r, w)
	if err != nil {
		return
	}
	defer conn.Close()
	defer func() { f.disconnects <- struct{}{} }()
	for {
		data, err := wsutil.ReadClientText(conn)
		if err != nil {
			return
		}
		var req struct {
			ID        int64          `json:"id"`
			Method    string         `json:"method"`
			SessionID string         `json:"sessionId,omitempty"`
			Params    map[string]any `json:"params"`
		}
		if json.Unmarshal(data, &req) != nil {
			return
		}
		f.mu.Lock()
		f.methods = append(f.methods, req.Method)
		if req.Method == "Target.attachToTarget" {
			f.attached = append(f.attached, req.Params["targetId"].(string))
		}
		f.mu.Unlock()
		result := any(map[string]any{})
		switch req.Method {
		case "Target.attachToTarget":
			result = map[string]any{"sessionId": "fixture-session"}
		case "Runtime.evaluate":
			result = map[string]any{"result": map[string]any{"type": "object", "className": "Window"}}
		case "Page.getFrameTree":
			result = map[string]any{"frameTree": map[string]any{"frame": map[string]any{"id": "frame-1", "loaderId": "loader-1", "url": "http://127.0.0.1/fixture", "securityOrigin": "http://127.0.0.1", "mimeType": "text/html"}}}
		case "DOM.getDocument":
			result = map[string]any{"root": map[string]any{"nodeId": 1, "backendNodeId": 1, "nodeType": 9, "nodeName": "#document", "localName": "", "nodeValue": ""}}
		}
		reply := map[string]any{"id": req.ID, "result": result}
		if req.SessionID != "" {
			reply["sessionId"] = req.SessionID
		}
		if f.failAttach && req.Method == "Target.attachToTarget" {
			delete(reply, "result")
			reply["error"] = map[string]any{"code": -32602, "message": "No target with given id found"}
		}
		payload, _ := json.Marshal(reply)
		if wsutil.WriteServerText(conn, payload) != nil {
			return
		}
	}
}

func TestAttachWireContractKeepsOwnedTargetOnCloseAndCancellation(t *testing.T) {
	for _, cancelParent := range []bool{false, true} {
		t.Run(map[bool]string{false: "close", true: "parent-cancel"}[cancelParent], func(t *testing.T) {
			f := &targetFixture{disconnects: make(chan struct{}, 4)}
			server := httptest.NewServer(http.HandlerFunc(f.serve))
			defer server.Close()
			endpoint := "ws" + strings.TrimPrefix(server.URL, "http")
			for i := 0; i < 2; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				s, err := Attach(ctx, endpoint, 42, "fixture-profile", "host-owned-target")
				if err != nil {
					cancel()
					t.Fatal(err)
				}
				if !s.Attached || s.TargetID != "host-owned-target" || string(chromedp.FromContext(s.Ctx).Target.TargetID) != s.TargetID {
					t.Fatal("attached to wrong target")
				}
				if cancelParent {
					cancel()
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				s.Close()
				cancel()
				select {
				case <-f.disconnects:
				case <-time.After(3 * time.Second):
					t.Fatal("transport remained connected")
				}
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.attached) != 2 || f.attached[0] != f.attached[1] {
				t.Fatalf("target changed: %v", f.attached)
			}
			for _, method := range f.methods {
				switch method {
				case "Target.closeTarget", "Browser.close", "Target.createTarget", "Target.getTargets":
					t.Fatalf("unexpected ownership/selection command: %s", method)
				}
			}
		})
	}
}

func TestAttachMissingTargetFailsWithoutReplacement(t *testing.T) {
	f := &targetFixture{disconnects: make(chan struct{}, 1), failAttach: true}
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Attach(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), 42, "fixture", "missing-target"); err == nil {
		t.Fatal("missing target accepted")
	}
	<-f.disconnects
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, method := range f.methods {
		if method != "Target.attachToTarget" {
			t.Fatalf("fallback command: %s", method)
		}
	}
}

func TestAttachRejectsEmptyTargetBeforeConnecting(t *testing.T) {
	if _, err := Attach(context.Background(), "ws://127.0.0.1:1", 1, "fixture", ""); err == nil {
		t.Fatal("empty target accepted")
	}
}
