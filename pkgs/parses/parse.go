package pasrses

import (
	"flag"
	"fmt"
	"os"
)

type Flag struct {
	FileName    string
	ProcessID   int
	ProcessName string
}

func usage() {
	fmt.Println("Usage: minidump.exe -f <file name> -p <process id> -n <process name>")
	fmt.Println("need either process id or process name and filename")
}
func Parse() *Flag {
	f := &Flag{}
	flag.StringVar(&f.FileName, "f", "", "File name to dump")
	flag.IntVar(&f.ProcessID, "p", 0, "Process ID to dump")
	flag.StringVar(&f.ProcessName, "n", "", "Process name to dump")
	flag.Parse()
	if f.ProcessID == 0 && f.ProcessName == "" {
		usage()
		os.Exit(1)
	}
	return f
}
