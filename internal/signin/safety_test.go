package signin

import "testing"

func TestClickSafetyUsesExactHostname(t *testing.T) {
	tests := []struct {
		name, host, text string
		allow            bool
	}{
		{"normal business page", "xsfw.gzist.edu.cn", "个人查寝 查寝时间段 点击签到 你已进入考勤登记范围", true},
		{"CAS", "ids.gzist.edu.cn", "点击签到", false},
		{"host read empty", "", "点击签到", false},
		{"suffix spoof", "xsfw.gzist.edu.cn.evil.example", "点击签到", false},
		{"prefix spoof", "notxsfw.gzist.edu.cn", "点击签到", false},
		{"no button", "xsfw.gzist.edu.cn", "个人查寝", false},
		{"out of range", "xsfw.gzist.edu.cn", "点击签到 不在考勤范围", false},
		{"off hours", "xsfw.gzist.edu.cn", "点击签到 非考勤时段", false},
		{"already signed", "xsfw.gzist.edu.cn", "点击签到 无需重复签到", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reason := clickSafetyHost(tc.host, tc.text)
			if (reason == "") != tc.allow {
				t.Fatalf("allow=%v reason=%q", tc.allow, reason)
			}
		})
	}
}
