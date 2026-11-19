package browserhost

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestConfirmedGrantKeepsHostOwnedTargetAcrossLeases(t *testing.T) {
	d, c, _ := newFakeDaemon(t, true)
	var previous TargetGrant
	for i := 0; i < 2; i++ {
		r, err := c.Reserve(context.Background(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		grant, err := c.ConfirmTarget(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		again, err := c.ConfirmTarget(context.Background(), r)
		if err != nil || again != grant {
			t.Fatalf("repeat changed grant: %v", err)
		}
		d.mu.Lock()
		valid := grant.TargetID == d.session.TargetID && grant.Endpoint == d.session.Endpoint && grant.Generation == d.sessionGen
		d.mu.Unlock()
		if !valid {
			t.Fatal("grant not bound to host snapshot")
		}
		if i > 0 && (grant.TargetID != previous.TargetID || grant.Endpoint != previous.Endpoint || grant.Generation != previous.Generation) {
			t.Fatal("normal release replaced owned target")
		}
		previous = grant
		c.release(r.ID)
	}
}

func TestConfirmRejectsClientTargetSelection(t *testing.T) {
	_, c, _ := newFakeDaemon(t, true)
	r, err := c.Reserve(context.Background(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"id": r.ID, "token": r.Token, "targetId": "foreign-tab"})
	resp, err := c.do(context.Background(), http.MethodPost, "/lease/confirm", body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("accepted target nomination: %d", resp.StatusCode)
	}
	grant, err := c.ConfirmTarget(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if grant.TargetID == "foreign-tab" {
		t.Fatal("client selected target")
	}
	c.release(r.ID)
}

func TestIncompleteTargetGrantAbortsBeforeAttach(t *testing.T) {
	for _, field := range []string{"targetId", "generation", "id"} {
		t.Run(field, func(t *testing.T) {
			d, c, f := newFakeDaemon(t, true)
			sessions := 0
			defer fakeAttach(t, &sessions)()
			c.http = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				resp, err := http.DefaultTransport.RoundTrip(r)
				if err != nil {
					return resp, err
				}
				if r.URL.Path == "/lease/confirm" && resp.StatusCode == http.StatusOK {
					var obj map[string]any
					err = json.NewDecoder(resp.Body).Decode(&obj)
					resp.Body.Close()
					if err != nil {
						return nil, err
					}
					delete(obj, field)
					data, _ := json.Marshal(obj)
					resp.Body = io.NopCloser(strings.NewReader(string(data)))
					resp.ContentLength = int64(len(data))
				}
				return resp, nil
			})}
			if _, _, err := c.Attach(context.Background(), time.Minute); err == nil {
				t.Fatal("incomplete grant accepted")
			}
			if sessions != 0 {
				t.Fatal("attached without complete host grant")
			}
			if len(f.closed) != 1 {
				t.Fatal("ambiguous activation was not revoked")
			}
			if d.Status().Leased {
				t.Fatal("revoked lease retained")
			}
		})
	}
}
