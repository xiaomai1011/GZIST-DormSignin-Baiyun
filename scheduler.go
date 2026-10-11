package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// Only account digests, dates, slots and confirmed-success booleans go on disk.
// No credentials, cookies or server response text are stored here.
type scheduleDay struct {
	Success bool            `json:"success"`
	Slots   map[string]bool `json:"slots"`
}
type scheduleLedger struct {
	mu   sync.Mutex
	path string
	Days map[string]map[string]*scheduleDay `json:"days"`
}
type scheduleTicket struct {
	Account, Date, Slot string
	ClaimedAt           time.Time
}

func accountKey(id string) string {
	if id == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("GZIST-DormSignin-Baiyun/account/v1\x00" + id))
	return hex.EncodeToString(sum[:])
}

// accountSettings isolates browser authentication as well as ledger state.
// Never copy or migrate the old shared profile into an account directory.
func accountSettings(cfg store.Settings, id, pass string, credErr error) (store.Settings, error) {
	if credErr != nil {
		return cfg, errors.New("无法读取账号凭据")
	}
	if id == "" || pass == "" {
		return cfg, errors.New("请先填写学号和密码")
	}
	if strings.TrimSpace(cfg.UserData) == "" {
		return cfg, errors.New("Edge 用户目录不能为空")
	}
	cfg.UserData = filepath.Join(cfg.UserData, "accounts-v1", accountKey(id))
	return cfg, nil
}

func openScheduleLedger(path string) (*scheduleLedger, error) {
	l := &scheduleLedger{path: path, Days: make(map[string]map[string]*scheduleDay)}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return l, err
	}
	if err = json.Unmarshal(b, l); err != nil {
		l.Days = make(map[string]map[string]*scheduleDay)
		return l, err
	}
	if l.Days == nil {
		l.Days = make(map[string]map[string]*scheduleDay)
	}
	return l, nil
}
func (l *scheduleLedger) entry(account, date string) *scheduleDay {
	if l.Days[date] == nil {
		l.Days[date] = make(map[string]*scheduleDay)
	}
	if l.Days[date][account] == nil {
		l.Days[date][account] = &scheduleDay{Slots: make(map[string]bool)}
	}
	d := l.Days[date][account]
	if d.Slots == nil {
		d.Slots = make(map[string]bool)
	}
	return d
}
func (l *scheduleLedger) succeeded(account string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	d := l.Days[now.Format("2006-01-02")][account]
	return account != "" && d != nil && d.Success
}
func (l *scheduleLedger) confirm(account, date string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if account == "" {
		return errors.New("empty success account")
	}
	l.entry(account, date).Success = true // keep suppression even if disk write fails
	return l.save()
}
func (l *scheduleLedger) save() error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(l.path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(l.path), ".schedule-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(name, l.path)
}
func scheduledTimeAllowed(now time.Time, cfg store.Settings) bool {
	// Match Runner's existing time guard; AttWindow is display-only.
	late, err := time.Parse("15:04", cfg.LateLine)
	if err != nil {
		late = time.Date(0, 1, 1, 23, 0, 0, 0, time.UTC)
	}
	return now.Hour() >= 21 && now.Hour()*60+now.Minute() < late.Hour()*60+late.Minute()
}
func containsSlot(times []string, slot string) bool {
	for _, s := range times {
		if s == slot {
			return true
		}
	}
	return false
}

// claim persists before jitter. Even a canceled/failed attempt consumes its slot;
// later configured slots remain available unless success has been confirmed.
func (l *scheduleLedger) claim(now time.Time, cfg store.Settings, account string, hasCredentials, running bool) (*scheduleTicket, error) {
	if cfg.Holiday || !hasCredentials || running || account == "" || !scheduledTimeAllowed(now, cfg) {
		return nil, nil
	}
	slot, date := now.Format("15:04"), now.Format("2006-01-02")
	if !containsSlot(cfg.Times, slot) {
		return nil, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	d := l.entry(account, date)
	if d.Success || d.Slots[slot] {
		return nil, nil
	}
	d.Slots[slot] = true
	if err := l.save(); err != nil {
		return nil, err
	} // fail closed; no repeated requests
	return &scheduleTicket{Account: account, Date: date, Slot: slot, ClaimedAt: now}, nil
}

// A jitter may cross a minute boundary but must not survive a clock jump,
// suspend/resume, day change, settings change, or a manual success.
func (l *scheduleLedger) eligible(t *scheduleTicket, now time.Time, cfg store.Settings, account string, hasCredentials, running bool) bool {
	if t == nil || cfg.Holiday || running || !hasCredentials || account != t.Account || now.Format("2006-01-02") != t.Date || now.Before(t.ClaimedAt) || now.Sub(t.ClaimedAt) > 2*time.Minute || !containsSlot(cfg.Times, t.Slot) || !scheduledTimeAllowed(now, cfg) {
		return false
	}
	// time.Now carries a monotonic clock: also compare stripped wall times
	// so changing the system clock cannot revive a stale scheduled slot.
	wallNow, wallClaim := now.Round(0), t.ClaimedAt.Round(0)
	if wallNow.Before(wallClaim) || wallNow.Sub(wallClaim) > 2*time.Minute {
		return false
	}
	return !l.succeeded(account, now)
}
