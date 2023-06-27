package log

import (
	"fmt"
	"go-minidump/pkgs/dump"
	"os"
	"path/filepath"
)

type Log interface {
	Info(string)
	Error(string)
}

func InfoDump(d dump.DumpState) {
	fmt.Println("[+] Dumping state ")
	fmt.Println("ProcessID: ", d.ProcessID)
	fmt.Println("FileName: ", d.FileName)
}
