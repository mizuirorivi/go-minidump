package dump

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	PROCESS_ALL_ACCESS        = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xffff
	SizeofProcessEntry32 uint = 568
)

var (
	MiniDumpWriteDump uintptr
	err               error
)

type Dumper interface {
	Dump() error
}
type DumperState struct {
	FileName      string
	ProcessID     int
	ProcessName   string
	ProcessHandle windows.Handle
	DumpFile      *os.File
}

func init() {
	dbghelp, err := syscall.LoadLibrary("dbghelp.dll")
	if err != nil {
		fmt.Printf("Error loading dbghelp.dll: %v\n", err)
		return
	}

	MiniDumpWriteDump, err = syscall.GetProcAddress(dbghelp, "MiniDumpWriteDump")
	if err != nil {
		fmt.Printf("Error getting MiniDumpWriteDump procedure address: %v\n", err)
		syscall.FreeLibrary(dbghelp)
		return
	}

}
func (d *DumperState) Dump() error {
	if err := d.createFile(); err != nil {
		return err
	}
	defer d.close()

	if d.ProcessID == 0 {
		if err := d.getProcessId(); err != nil {
			return err
		}
	}

	if err := d.openProcess(windows.ABOVE_NORMAL_PRIORITY_CLASS); err != nil {
		return err
	}

	if err := d.writeMiniDump(); err != nil {
		return err
	}

	fmt.Println("[+]Dump successful")
	return nil
}

func (d *DumperState) createFile() error {
	file, err := os.Create(d.FileName)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	d.DumpFile = file
	return nil
}

func (d *DumperState) openProcess(priority uint32) error {
	const (
		STANDARD_RIGHTS_REQUIRED = 0x000F0000
		SYNCHRONIZE              = 0x00100000
		PROCESS_ALL_ACCESS       = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)
	)

	if err := enableDebugPrivilege(); err != nil {
		return fmt.Errorf("failed to enable SeDebugPrivilege: %v", err)
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess := kernel32.NewProc("OpenProcess")

	handle, _, _ := procOpenProcess.Call(
		uintptr(PROCESS_ALL_ACCESS),
		0,
		uintptr(d.ProcessID),
	)

	if handle == 0 {
		return fmt.Errorf("[-]error opening process")
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
		return fmt.Errorf("error creating toolhelp32 snapshot: %w", err)
	}
	defer syscall.CloseHandle(snapshot)

	var entry syscall.ProcessEntry32
	entry.Size = uint32(SizeofProcessEntry32)

	err = syscall.Process32First(snapshot, &entry)
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

	dbg := syscall.NewLazyDLL("dbghelp.dll")
	mini := dbg.NewProc("MiniDumpWriteDump")

	handle, _, _ := mini.Call(
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
