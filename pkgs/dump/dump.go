package dump

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

const (
	PROCESS_ALL_ACCESS        = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xffff
	SizeofProcessEntry32 uint = 568
)

var (
	dbghelp, _           = syscall.LoadLibrary("dbghelp.dll")
	MiniDumpWriteDump, _ = syscall.GetProcAddress(dbghelp, "MiniDumpWriteDump")
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
		PROCESS_QUERY_INFORMATION = 0x0400
		PROCESS_VM_READ           = 0x0010
	)
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess := kernel32.NewProc("OpenProcess")

	handle, _, _ := procOpenProcess.Call(
		PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,
		0,
		uintptr(d.ProcessID),
	)

	if handle == 0 {
		return fmt.Errorf("[-]error opening process")
	}

	d.ProcessHandle = windows.Handle(handle)
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

	ret, _, callErr := syscall.Syscall9(
		uintptr(MiniDumpWriteDump),
		uintptr(7),

		uintptr(d.ProcessHandle),
		uintptr(d.ProcessID),
		uintptr(d.DumpFile.Fd()),
		uintptr(2),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		0, 0,
	)
	if callErr != 0 {
		return fmt.Errorf("error calling MiniDumpWriteDump: %w", callErr)
	}

	if int(ret) == 0 {
		return fmt.Errorf("MiniDumpWriteDump returned 0")
	}

	return nil
}

func (d *DumperState) close() {
	if d.DumpFile != nil {
		d.DumpFile.Close()
	}
	windows.CloseHandle(d.ProcessHandle)
}
