package dump

import (
	"fmt"
	"github.com/mizuirorivi/go-minidump/pkgs/log"
	"golang.org/x/sys/windows"
	"os"
	"syscall"
)

const PROCESS_ALL_ACCESS = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xffff

var (
	dbghelp, _           = syscall.LoadLibrary("dbghelp.dll")
	MiniDumpWriteDump, _ = syscall.GetProcAddress(dbghelp, "MiniDumpWriteDump")
)

// create interface
type Dump interface {
	CreateDump() error
	CreateFile() error
	OpenProcess() error
	DumpA() error
	MiniDumpWriteDump() error
	Run() error
	Close() error
}

// create struct
type DumpState struct {
	FileName      string
	ProcessID     int
	ProcessHandle windows.Handle
	DumpFile      *os.File
}

func (d DumpState) Run() {
	d.DumpA()
}

func (d DumpState) Close() {
	d.DumpFile.Close()
	windows.CloseHandle(d.ProcessHandle)
}

func (d DumpState) OpenProcess(priority uint32) error {
	processHandle, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(d.ProcessID))

	if err != nil {
		return err
	}
	err = windows.SetPriorityClass(processHandle, priority)
	if err != nil {
		return err
	}
	d.ProcessHandle = processHandle
	return nil
}
func (d DumpState) CreateFile() error {
	file, err := os.Create(d.FileName)
	if err != nil {
		return err
	}
	d.DumpFile = file
	return nil
}

func (d DumpState) MiniDumpWriteDump() (int, error) {
	ret, _, callErr := syscall.Syscall9(
		uintptr(MiniDumpWriteDump),
		uintptr(7),
		uintptr(d.ProcessHandle),
		uintptr(d.ProcessID),
		uintptr(d.DumpFile.Fd()),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		0, 0,
	)
	if callErr != 0 {
		return 0, fmt.Errorf("[-]Error calling MiniDumpWriteDump", callErr)
	}
	result := int(ret)
	return result, nil
}

/*
*
  - Use MiniDumpWriteDump from dbghelp.dll
    Dump from process id to file
*/
func (d DumpState) DumpA() error {
	d.CreateFile()
	defer d.Close()
	log.InfoDump(d)
	d.OpenProcess(windows.ABOVE_NORMAL_PRIORITY_CLASS)

	ret, err := d.MiniDumpWriteDump()
	if err != nil {
		return err
	}
	if ret == 0 {
		return fmt.Errorf("[-]Error calling MiniDumpWriteDump")
	}

	fmt.Println("[+]Dump successful")
	return nil
}
