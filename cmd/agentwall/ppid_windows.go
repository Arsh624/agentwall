package main

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// agentPID is the process that started us, looking past cmd /c and PowerShell
// wrappers: on Windows they stay alive as our parent, so every wrapped server
// would get its own parent pid and cross-server taint would be lost.
func agentPID() int {
	pid := os.Getppid()
	for range 4 { // wrappers rarely nest; stop before a loop on a reused pid
		parent, exe, ok := process(pid)
		if !ok || !isShell(exe) {
			break
		}
		pid = parent
	}
	return pid
}

func isShell(exe string) bool {
	switch strings.ToLower(exe) {
	case "cmd.exe", "powershell.exe", "pwsh.exe", "sh.exe", "bash.exe":
		return true
	}
	return false
}

// process returns the parent pid and executable name of pid.
func process(pid int) (parent int, exe string, ok bool) {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, "", false
	}
	defer syscall.CloseHandle(snap)
	var e syscall.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = syscall.Process32First(snap, &e); err == nil; err = syscall.Process32Next(snap, &e) {
		if e.ProcessID == uint32(pid) {
			return int(e.ParentProcessID), syscall.UTF16ToString(e.ExeFile[:]), true
		}
	}
	return 0, "", false
}
