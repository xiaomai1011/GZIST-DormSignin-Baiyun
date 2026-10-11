//go:build windows

package edge

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PROC_THREAD_ATTRIBUTE_JOB_LIST is available on Windows 10 and later. There is
// deliberately no assign-after-create fallback: even a suspended process can be
// orphaned if its owner dies between creation and assignment.
const procThreadAttributeJobList = 0x0002000d

type jobBasicAccountingInformation struct {
	TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime int64
	TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses     uint32
}

// stopJob waits for the entire tree, not merely the original browser process.
// Closing the handle is still mandatory on error (KILL_ON_JOB_CLOSE is our final
// safeguard), but callers must not treat an unsuccessful barrier as clean exit.
func stopJob(job windows.Handle) (result error) {
	defer func() {
		if err := windows.CloseHandle(job); err != nil {
			result = errors.Join(result, fmt.Errorf("close Edge job: %w", err))
		}
	}()
	if err := windows.TerminateJobObject(job, 1); err != nil {
		result = fmt.Errorf("terminate Edge job: %w", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		var info jobBasicAccountingInformation
		err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil)
		if err != nil {
			return errors.Join(result, fmt.Errorf("query Edge job exit barrier: %w", err))
		}
		if info.ActiveProcesses == 0 {
			return result
		}
		if time.Now().After(deadline) {
			return errors.Join(result, fmt.Errorf("Edge job exit barrier timed out after 10s: %d active processes", info.ActiveProcesses))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// startOwnedProcess owns the StdoutPipe writer supplied by the caller. exec.Cmd
// is used only as configuration: native creation atomically places the new
// process in the non-inheritable kill-on-close job before any code can execute.
func startOwnedProcess(cmd *exec.Cmd) (func() error, error) {
	out, ok := cmd.Stdout.(*os.File)
	if !ok || out == nil {
		return nil, errors.New("Edge stdout must be an os.File from StdoutPipe")
	}
	// cmd.Start normally closes this parent-side writer. We bypass Start, so we
	// must do it ourselves on success AND failure, otherwise the reader never EOFs.
	defer out.Close()
	if cmd.Stderr != cmd.Stdout {
		return nil, errors.New("Edge stderr must share the stdout pipe")
	}
	if cmd.Process != nil {
		return nil, errors.New("Edge process already started")
	}
	if cmd.Err != nil {
		return nil, cmd.Err
	}
	input, ok := cmd.Stdin.(*os.File)
	if cmd.Stdin == nil {
		var err error
		input, err = os.Open(os.DevNull)
		if err != nil {
			return nil, err
		}
		defer input.Close()
	} else if !ok || input == nil {
		return nil, errors.New("Edge stdin must be nil or an os.File")
	}

	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			windows.CloseHandle(job)
		}
	}()
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return nil, fmt.Errorf("configure Edge job: %w", err)
	}

	// Inherit exactly the standard handles. In particular, never inherit the job
	// itself, or an owner's crash would no longer close the last job handle.
	handles := make([]windows.Handle, 2)
	for i, file := range []*os.File{input, out} {
		if err = windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(file.Fd()), windows.CurrentProcess(), &handles[i], 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
			return nil, fmt.Errorf("duplicate Edge standard handle: %w", err)
		}
		defer windows.CloseHandle(handles[i])
	}
	attrs, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return nil, err
	}
	defer attrs.Delete()
	if err = attrs.Update(procThreadAttributeJobList, unsafe.Pointer(&job), unsafe.Sizeof(job)); err != nil {
		return nil, fmt.Errorf("set atomic Edge job ownership: %w", err)
	}
	if err = attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return nil, err
	}
	startup := windows.StartupInfoEx{ProcThreadAttributeList: attrs.List()}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.Flags = windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW
	startup.ShowWindow = windows.SW_HIDE
	startup.StdInput, startup.StdOutput, startup.StdErr = handles[0], handles[1], handles[1]
	app, err := windows.UTF16PtrFromString(cmd.Path)
	if err != nil {
		return nil, err
	}
	args := cmd.Args
	if len(args) == 0 {
		args = []string{cmd.Path}
	}
	commandLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(args))
	if err != nil {
		return nil, err
	}
	var directory *uint16
	if cmd.Dir != "" {
		directory, err = windows.UTF16PtrFromString(cmd.Dir)
		if err != nil {
			return nil, err
		}
	}
	env := cmd.Environ()
	for _, value := range env {
		if strings.ContainsRune(value, 0) {
			return nil, errors.New("NUL in Edge environment")
		}
	}
	environment := utf16.Encode([]rune(strings.Join(env, "\x00") + "\x00\x00"))
	var native windows.ProcessInformation
	if err = windows.CreateProcess(app, commandLine, nil, nil, true, windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT, &environment[0], directory, &startup.StartupInfo, &native); err != nil {
		return nil, fmt.Errorf("create atomically owned Edge process: %w", err)
	}
	defer windows.CloseHandle(native.Process)
	defer windows.CloseHandle(native.Thread)
	process, err := os.FindProcess(int(native.ProcessId))
	if err != nil {
		transferred = true
		return nil, errors.Join(fmt.Errorf("open owned Edge process: %w", err), stopJob(job))
	}
	cmd.Process = process
	transferred = true
	var once sync.Once
	var stopErr error
	return func() error { once.Do(func() { stopErr = stopJob(job) }); return stopErr }, nil
}

// cmd.Wait requires cmd.Start's private bookkeeping and closes pipe readers;
// neither is appropriate for a process created with native StartupInfoEx.
func waitOwnedProcess(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return errors.New("Edge process has not started")
	}
	state, err := cmd.Process.Wait()
	cmd.ProcessState = state
	if err != nil {
		return fmt.Errorf("wait Edge process: %w", err)
	}
	if !state.Success() {
		return &exec.ExitError{ProcessState: state}
	}
	return nil
}

// An exclusive handle, not a persistent PID file: released automatically on crash.
func lockProfile(path string) (func(), error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, fmt.Errorf("浏览器目录正在被其他实例使用或不可写: %w", err)
	}
	return func() { _ = windows.CloseHandle(h) }, nil
}
