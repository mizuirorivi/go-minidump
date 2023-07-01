package dump

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	STANDARD_RIGHTS_REQUIRED = 0x000F0000
	SYNCHRONIZE              = 0x00100000
	PROCESS_ALL_ACCESS       = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)
)

type Dumper interface {
	Dump() error
}
type DumperState struct {
	FileName      string         // dump file name
	ProcessID     int            // process id
	ProcessName   string         // process name
	ProcessHandle windows.Handle // process handle
	DumpFile      *os.File       // file handle for dump
}

func (d *DumperState) Dump() error {
	defer d.close()

	if d.ProcessID == 0 {
		if err := d.getProcessId(); err != nil {
			return err
		}
	}

	if err := d.createFile(); err != nil {
		return err
	}

	if err := d.openProcess(windows.ABOVE_NORMAL_PRIORITY_CLASS); err != nil {
		return err
	}

	if err := d.writeMiniDump(); err != nil {
		return err
	}

	fmt.Println("[+]Dump successful -> ", d.FileName)
	return nil
}

func (d *DumperState) createFile() error {
	// define default file name
	if d.FileName == "" {
		f := d.ProcessName + "_" + strconv.Itoa(d.ProcessID)
		d.FileName = strings.ReplaceAll(f, ".", "_") + ".dmp"
	}
	file, err := os.Create(d.FileName)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	d.DumpFile = file
	return nil
}

func (d *DumperState) openProcess(priority uint32) error {

	if err := enableDebugPrivilege(); err != nil {
		return fmt.Errorf("failed to enable SeDebugPrivilege: %v", err)
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess := kernel32.NewProc("OpenProcess")

	handle, _, callerr := procOpenProcess.Call(
		uintptr(PROCESS_ALL_ACCESS),
		0,
		uintptr(d.ProcessID),
	)

	if handle == 0 {
		return fmt.Errorf("[-]error opening process: %v", callerr)
	}

	d.ProcessHandle = windows.Handle(handle)
	return nil
}

func enableDebugPrivilege() error {
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeDebugPrivilege"), &luid); err != nil {
		return err
	}

	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES, &token); err != nil {
		return err
	}
	defer token.Close()

	tokenPrivileges := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}

	if err := windows.AdjustTokenPrivileges(token, false, &tokenPrivileges, uint32(unsafe.Sizeof(tokenPrivileges)), nil, nil); err != nil {
		return err
	}

	return nil
}

func (d *DumperState) getProcessId() error {
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return fmt.Errorf("[-]error creating toolhelp32 snapshot: %w", err)
	}
	defer syscall.CloseHandle(snapshot)

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = syscall.Process32First(snapshot, &entry)
	if err != nil {
		return fmt.Errorf("[-]error getting first process: %w", err)
	}

	for err == nil {
		if syscall.UTF16ToString(entry.ExeFile[:]) == d.ProcessName {
			d.ProcessID = int(entry.ProcessID)
			return nil
		}
		err = syscall.Process32Next(snapshot, &entry)
	}
	return fmt.Errorf("[-] process not found")
}

func (d *DumperState) writeMiniDump() error {
	const (
		MiniDumpWithFullMemory = 2 // argument of MiniDumpWriteDump for full dump
	)

	dbghelp := syscall.NewLazyDLL("dbghelp.dll")
	MiniDumpWriteDump := dbghelp.NewProc("MiniDumpWriteDump")

	handle, _, _ := MiniDumpWriteDump.Call(
		uintptr(d.ProcessHandle),
		uintptr(d.ProcessID),
		uintptr(d.DumpFile.Fd()),
		uintptr(MiniDumpWithFullMemory),
		uintptr(0),
		uintptr(0),
		uintptr(0),
	)

	if handle == 0 {
		return fmt.Errorf("[-]error opening process")
	}

	return nil
}

func (d *DumperState) close() {
	if d.DumpFile != nil {
		d.DumpFile.Close()
	}
	windows.CloseHandle(d.ProcessHandle)
}
