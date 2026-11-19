package browserhost

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fakeAttach(t *testing.T, sessions *int) func() {
	t.Helper()
	old := attachSession
	attachSession = func(context.Context, string, int, string, string) (*edge.Session, error) {
		*sessions++
		return &edge.Session{PID: 999, Endpoint: "ws://127.0.0.1:1/devtools/browser/fake"}, nil
	}
	return func() { attachSession = old }
}

// A confirm reply that never arrives must not leave an activated lease behind:
// the client knows the reservation identity and revokes it before reporting.
func TestALostConfirmReplyStillRevokesTheLease(t *testing.T) {
	d, c, f := newFakeDaemon(t, true)
	sessions := 0
	defer fakeAttach(t, &sessions)()

	c.http = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil {
			return nil, err
		}
		if r.URL.Path == "/lease/confirm" {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			return nil, errors.New("模拟确认响应丢失")
		}
		return resp, nil
	})}

	if _, _, err := c.Attach(context.Background(), time.Minute); err == nil {
		t.Fatal("确认响应丢失应向上返回错误")
	}
	if sessions != 0 {
		t.Fatal("确认失败后不应附加浏览器")
	}
	if st := d.Status(); st.Leased {
		t.Fatal("租约应已被撤销，不能留给下一轮")
	}
	if len(f.closed) == 0 {
		t.Fatal("已激活的浏览器应被撤销，而不是当作从未使用")
	}
}

// When the revocation itself fails, the error must carry both causes; the run
// cannot silently proceed as if cleanup had succeeded.
func TestAFailedRevocationIsReportedWithTheLostReply(t *testing.T) {
	_, c, _ := newFakeDaemon(t, true)
	sessions := 0
	defer fakeAttach(t, &sessions)()

	c.http = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/lease/abort" {
			return nil, errors.New("模拟撤销失败")
		}
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil {
			return nil, err
		}
		if r.URL.Path == "/lease/confirm" {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			return nil, errors.New("模拟确认响应丢失")
		}
		return resp, nil
	})}

	_, _, err := c.Attach(context.Background(), time.Minute)
	if err == nil {
		t.Fatal("应返回错误")
	}
	if !contains(err.Error(), "确认响应丢失") || !contains(err.Error(), "撤销") {
		t.Fatalf("错误应同时包含两个原因，实得 %v", err)
	}
}

// A confirm that arrives after its lease expired must not be handed the browser
// of the newer lease: the id is gone, so the answer is a conflict without an
// endpoint.
func TestALateConfirmNeverGetsTheNewBrowser(t *testing.T) {
	d, c, f := newFakeDaemon(t, true)
	sessions := 0
	defer fakeAttach(t, &sessions)()

	invite := c.rawInvite(t, time.Second)
	var offer leaseOffer
	if err := json.NewDecoder(invite.Body).Decode(&offer); err != nil {
		t.Fatal(err)
	}
	_ = invite.Body.Close()
	first := c.postJSON(t, "/lease/confirm", `{"id":`+itoa(offer.ID)+`,"token":"`+offer.Token+`"}`)
	_ = first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("首次确认应成功，实得 %d", first.StatusCode)
	}

	time.Sleep(1400 * time.Millisecond) // TTL 到期，宿主撤销并释放槽位
	if st := d.Status(); st.PID != 0 || len(f.closed) == 0 {
		t.Fatalf("过期应撤销浏览器，实得 PID=%d closed=%v", st.PID, f.closed)
	}

	second := c.rawLease(t, time.Minute)
	_ = second.Body.Close()
	if second.StatusCode != http.StatusOK {
		t.Fatalf("新租约应成功，实得 %d", second.StatusCode)
	}

	late := c.postJSON(t, "/lease/confirm", `{"id":`+itoa(offer.ID)+`,"token":"`+offer.Token+`"}`)
	body, _ := io.ReadAll(late.Body)
	_ = late.Body.Close()
	if late.StatusCode == http.StatusOK {
		t.Fatal("过期租约的确认不能被接受")
	}
	if contains(string(body), "ws://") || contains(string(body), "devtools") {
		t.Fatalf("过期确认的响应里出现了新会话的 Endpoint: %s", body)
	}
}

// Close racing a confirm: whichever side wins, the client must not receive an
// endpoint from a host that is shutting down.
func TestAConfirmRacingCloseFailsClosed(t *testing.T) {
	d, c, _ := newFakeDaemon(t, true)
	sessions := 0
	defer fakeAttach(t, &sessions)()

	reached := make(chan struct{})
	release := make(chan struct{})
	var once bool
	c.http = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/lease/confirm" && !once {
			once = true
			close(reached)
			<-release
		}
		return http.DefaultTransport.RoundTrip(r)
	})}

	done := make(chan error, 1)
	go func() {
		_, _, err := c.Attach(context.Background(), time.Minute)
		done <- err
	}()
	<-reached
	closed := make(chan error, 1)
	go func() { closed <- d.Close() }()
	time.Sleep(100 * time.Millisecond)
	close(release)

	if err := <-done; err == nil {
		t.Fatal("关闭过程中的确认不能成功")
	}
	if err := <-closed; err != nil {
		t.Fatalf("Close 应完成：%v", err)
	}
	if sessions != 0 {
		t.Fatal("没有拿到 Endpoint 就不能附加")
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
