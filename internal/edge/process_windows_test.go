//go:build windows

package edge

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
	"golang.org/x/sys/windows"
)

// This helper's first action verifies its creation-time job ownership, before
// waiting for any parent handshake. Querying with a nil handle inspects its own
// job, including the kill-on-owner-close guarantee.
func TestOwnedProcessAtomicJobAndEOF(t *testing.T) {
	if os.Getenv("DORMSIGN_NATIVE_HELPER") == "1" {
		var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		err := windows.QueryInformationJobObject(0, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil)
		if err != nil || info.BasicLimitInformation.LimitFlags&windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0 {
			fmt.Fprintf(os.Stderr, "missing creation-time kill-on-close job: %v flags=%x", err, info.BasicLimitInformation.LimitFlags)
			os.Exit(91)
		}
		fmt.Fprint(os.Stdout, "owned-at-entry")
		if os.Getenv("DORMSIGN_NATIVE_EXIT") == "7" {
			os.Exit(7)
		}
		os.Exit(0)
	}
	for _, exit := range []string{"0", "7"} {
		t.Run("exit="+exit, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestOwnedProcessAtomicJobAndEOF$")
			cmd.Env = append(os.Environ(), "DORMSIGN_NATIVE_HELPER=1", "DORMSIGN_NATIVE_EXIT="+exit)
			cmd.Dir = t.TempDir()
			pipe, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer pipe.Close()
			cmd.Stderr = cmd.Stdout
			stop, err := startOwnedProcess(cmd)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := stop(); err != nil {
					t.Errorf("job exit barrier: %v", err)
				}
			}()
			result := make(chan error, 1)
			go func() {
				output, err := io.ReadAll(pipe)
				if err == nil && string(output) != "owned-at-entry" {
					err = fmt.Errorf("unexpected child output %q", output)
				}
				result <- err
			}()
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("stdout never reached EOF; parent writer or job handle leaked")
			}
			err = waitOwnedProcess(cmd)
			if exit == "0" && err != nil {
				t.Fatal(err)
			}
			if exit == "7" {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 {
					t.Fatalf("expected exit code 7, got %v", err)
				}
			}
			if err := stop(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOwnedProcessCreateFailureClosesWriter(t *testing.T) {
	cmd := exec.Command(filepath.Join(t.TempDir(), "missing.exe"))
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	cmd.Stderr = cmd.Stdout
	if _, err = startOwnedProcess(cmd); err == nil {
		t.Fatal("missing executable started")
	}
	result := make(chan error, 1)
	go func() { _, err := io.Copy(io.Discard, pipe); result <- err }()
	select {
	case err := <-result:
		if err != nil && !strings.Contains(err.Error(), "closed") {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("failed creation leaked parent writer")
	}
}

// The helper deliberately calls os.Exit without Session.Close, modelling a GUI
// crash/force kill. Windows must still reclaim the entire real Edge tree.
func TestJobSurvivesOwnerCrash(t *testing.T) {
	if os.Getenv("DORMSIGN_CRASH_HELPER") == "1" {
		cfg := store.Defaults()
		cfg.UserData = os.Getenv("DORMSIGN_CRASH_PROFILE")
		s, err := Launch(cfg)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
		if err != nil {
			t.Fatal(err)
		}
		parents := map[uint32]uint32{}
		entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
		for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
			parents[entry.ProcessID] = entry.ParentProcessID
		}
		windows.CloseHandle(snapshot)
		owned := map[uint32]bool{uint32(s.PID): true}
		for changed := true; changed; {
			changed = false
			for pid, parent := range parents {
				if owned[parent] && !owned[pid] {
					owned[pid] = true
					changed = true
				}
			}
		}
		pids := []uint32{}
		for pid := range owned {
			pids = append(pids, pid)
		}
		b, _ := json.Marshal(pids)
		if err := os.WriteFile(os.Getenv("DORMSIGN_CRASH_RESULT"), b, 0600); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)
	}
	if os.Getenv("DORMSIGN_EDGE_TEST") != "1" {
		t.Skip("opt-in real Edge crash test")
	}
	dir := t.TempDir()
	result := filepath.Join(dir, "pids.json")
	cmd := exec.Command(os.Args[0], "-test.run=^TestJobSurvivesOwnerCrash$")
	cmd.Env = append(os.Environ(), "DORMSIGN_CRASH_HELPER=1", "DORMSIGN_CRASH_PROFILE="+filepath.Join(dir, "profile"), "DORMSIGN_CRASH_RESULT="+result)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var pids []uint32
	if err = json.Unmarshal(b, &pids); err != nil {
		t.Fatal(err)
	}
	if len(pids) < 2 {
		t.Fatalf("no child processes observed: %v", pids)
	}
	for _, pid := range pids {
		h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
		if err == windows.ERROR_INVALID_PARAMETER {
			continue
		}
		if err != nil {
			t.Fatalf("inspect pid %d: %v", pid, err)
		}
		status, err := windows.WaitForSingleObject(h, uint32((5*time.Second)/time.Millisecond))
		windows.CloseHandle(h)
		if err != nil || status != windows.WAIT_OBJECT_0 {
			t.Fatalf("orphan pid=%d status=%d err=%v", pid, status, err)
		}
	}
	t.Logf("owner exited without cleanup; all %d browser processes terminated", len(pids))
}
