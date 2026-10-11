// Package store keeps the dorm-signin configuration and the student
// credentials. Config lives in settings.json in the user data dir; the
// student ID and password live in the OS credential store (falling back
// to a 0600 file). The PowerShell version's config.json (Chinese keys)
// is imported on first run.
package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/zalando/go-keyring"
)

const (
	service = "io.github.xiaomai1011.gzist-dormsignin"
	idUser  = "student-id"
	pwUser  = "student-pw"
)

// Settings mirrors the PowerShell config.json fields the Go rewrite
// actually uses. Defaults match the Baiyun campus deployment.
type Settings struct {
	URL       string `json:"url"`
	EdgePath  string `json:"edgePath"`
	UA        string `json:"userAgent"`
	ViewW     int    `json:"viewW"`
	ViewH     int    `json:"viewH"`
	DebugPort int    `json:"debugPort"`
	UserData  string `json:"userDataDir"` // relative to the exe dir unless absolute

	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	AccM    float64 `json:"accM"`
	GeoOn   bool    `json:"geoOn"`
	GeoMust bool    `json:"geoMust"`

	AttWindow string   `json:"attWindow"` // display, e.g. "21:30~23:00"
	LateLine  string   `json:"lateLine"`  // "23:00" — past this: give up, never late
	Times     []string `json:"times"`     // daily trigger times, e.g. 21:32/21:42/21:52

	Holiday   bool    `json:"holiday"` // away from school: scheduler paused
	AutoLogin bool    `json:"autoLogin"`
	CapMaxTry int     `json:"capMaxTry"`
	ConfThr   float64 `json:"confThr"`

	ClickSignX int `json:"clickSignX"` // fallback page coords for the sign button
	ClickSignY int `json:"clickSignY"`
}

// Defaults returns the Baiyun-campus defaults.
func Defaults() Settings {
	return Settings{
		URL:       "https://xsfw.gzist.edu.cn/xsfw/sys/swmzncqapp/*default/index.do#/xscq/grcq",
		EdgePath:  `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		UA:        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0",
		ViewW:     430,
		ViewH:     900,
		DebugPort: 9337,
		UserData:  "edge-userdata",

		Lat:     23.262197, // 白云校区 · 太和镇兴太三路638号（WGS-84）
		Lon:     113.451911,
		AccM:    20,
		GeoOn:   true,
		GeoMust: true,

		AttWindow: "21:30~23:00",
		LateLine:  "23:00",
		Times:     []string{"21:30", "21:40", "21:50", "22:00"},

		Holiday:   false,
		AutoLogin: true,
		CapMaxTry: 8,
		ConfThr:   0.55,

		ClickSignX: 208,
		ClickSignY: 474,
	}
}

type Keyring interface {
	Set(service, user, password string) error
	Get(service, user string) (string, error)
	Delete(service, user string) error
}

type osKeyring struct{}

func (osKeyring) Set(s, u, p string) error        { return keyring.Set(s, u, p) }
func (osKeyring) Get(s, u string) (string, error) { return keyring.Get(s, u) }
func (osKeyring) Delete(s, u string) error        { return keyring.Delete(s, u) }

// Store reads and writes settings and credentials.
type Store struct {
	Dir     string
	Keyring Keyring
}

func New(dir string) *Store { return &Store{Dir: dir, Keyring: osKeyring{}} }

func (s *Store) settingsPath() string { return filepath.Join(s.Dir, "settings.json") }
func (s *Store) secretPath() string   { return filepath.Join(s.Dir, "secret") }

// Load returns the saved settings, or the Baiyun defaults.
func (s *Store) Load() Settings {
	st := Defaults()
	b, err := os.ReadFile(s.settingsPath())
	if err == nil {
		json.Unmarshal(b, &st)
	}
	if len(st.Times) == 0 {
		st.Times = []string{"21:32", "21:42", "21:52"}
	}
	return st
}

// Save writes the settings.
func (s *Store) Save(st Settings) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	return os.WriteFile(s.settingsPath(), b, 0o600)
}

// Credentials returns the student ID and password ("", "", nil) when unset.
func (s *Store) Credentials() (id, pass string, err error) {
	id, err = s.Keyring.Get(service, idUser)
	if err != nil {
		id = s.readFile(idUser + ".txt")
	}
	pass, err = s.Keyring.Get(service, pwUser)
	if err != nil {
		pass = s.readFile(pwUser + ".txt")
	}
	return id, pass, nil
}

// SetCredentials stores both values; insecure reports the file fallback.
func (s *Store) SetCredentials(id, pass string) (insecure bool, err error) {
	insecure = false
	if err := s.Keyring.Set(service, idUser, id); err != nil {
		if e := s.writeFile(idUser+".txt", id); e != nil {
			return false, e
		}
		insecure = true
	} else {
		os.Remove(filepath.Join(s.Dir, idUser+".txt"))
	}
	if err := s.Keyring.Set(service, pwUser, pass); err != nil {
		if e := s.writeFile(pwUser+".txt", pass); e != nil {
			return false, e
		}
		insecure = true
	} else {
		os.Remove(filepath.Join(s.Dir, pwUser+".txt"))
	}
	return insecure, nil
}

func (s *Store) readFile(name string) string {
	b, _ := os.ReadFile(filepath.Join(s.Dir, name))
	return strings.TrimSpace(string(b))
}

func (s *Store) writeFile(name, val string) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.Dir, name), []byte(val), 0o600)
}

// DeleteCredentials forgets both values.
func (s *Store) DeleteCredentials() {
	s.Keyring.Delete(service, idUser)
	s.Keyring.Delete(service, pwUser)
	os.Remove(filepath.Join(s.Dir, idUser+".txt"))
	os.Remove(filepath.Join(s.Dir, pwUser+".txt"))
}

// ImportLegacy reads the PS-era config.json (Chinese keys) and fills
// in whatever it recognizes. It returns a short log line, or "" when
// there was nothing to import.
func (s *Store) ImportLegacy() string {
	// candidates: exe dir and cwd
	var paths []string
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, filepath.Join(filepath.Dir(exe), "config.json"))
	}
	paths = append(paths, "config.json")
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			return "旧版 config.json 存在但无法解析: " + err.Error()
		}
		st := s.Load()
		get := func(keys ...string) any {
			var cur any = m
			for _, k := range keys {
				mm, ok := cur.(map[string]any)
				if !ok {
					return nil
				}
				cur = mm[k]
			}
			return cur
		}
		setF := func(dst *float64, v any) {
			switch x := v.(type) {
			case float64:
				*dst = x
			case string:
				*dst, _ = strconv.ParseFloat(strings.TrimSpace(x), 64)
			}
		}
		setS := func(dst *string, v any) {
			if x, ok := v.(string); ok {
				*dst = x
			}
		}
		setB := func(dst *bool, v any) {
			switch x := v.(type) {
			case bool:
				*dst = x
			case string:
				*dst = x == "true"
			}
		}
		if v := get("url"); v != nil {
			setS(&st.URL, v)
		}
		if v := get("edgePath"); v != nil {
			setS(&st.EdgePath, v)
		}
		if v := get("userAgent"); v != nil {
			setS(&st.UA, v)
		}
		if v := get("viewport", "width"); v != nil {
			if x, ok := v.(float64); ok {
				st.ViewW = int(x)
			}
		}
		if v := get("viewport", "height"); v != nil {
			if x, ok := v.(float64); ok {
				st.ViewH = int(x)
			}
		}
		if v := get("_定位注入", "调试端口"); v != nil {
			if x, ok := v.(float64); ok {
				st.DebugPort = int(x)
			}
		}
		if v := get("_定位注入", "纬度"); v != nil {
			setF(&st.Lat, v)
		}
		if v := get("_定位注入", "经度"); v != nil {
			setF(&st.Lon, v)
		}
		if v := get("_定位注入", "精度米"); v != nil {
			setF(&st.AccM, v)
		}
		if v := get("_定位注入", "启用"); v != nil {
			setB(&st.GeoOn, v)
		}
		if v := get("_定位注入", "必须通过"); v != nil {
			setB(&st.GeoMust, v)
		}
		if v := get("_时序要求", "晚归线"); v != nil {
			setS(&st.LateLine, v)
		}
		if v := get("_自动登录", "启用"); v != nil {
			setB(&st.AutoLogin, v)
		}
		if v := get("_自动登录", "验证码最大尝试"); v != nil {
			if x, ok := v.(float64); ok {
				st.CapMaxTry = int(x)
			}
		}
		if v := get("_自动登录", "置信度阈值"); v != nil {
			setF(&st.ConfThr, v)
		}
		if v := get("clicks", "签到按钮", "x"); v != nil {
			if x, ok := v.(float64); ok {
				st.ClickSignX = int(x)
			}
		}
		if v := get("clicks", "签到按钮", "y"); v != nil {
			if x, ok := v.(float64); ok {
				st.ClickSignY = int(x)
			}
		}
		if err := s.Save(st); err != nil {
			return "导入旧配置失败: " + err.Error()
		}
		return "已从旧版 config.json 导入配置（" + p + "）—— 账号密码需在界面重新填写一次"
	}
	return ""
}

// ErrNoCredentials guards against empty credentials sneaking into a run.
var ErrNoCredentials = errors.New("未填写学号或密码")
