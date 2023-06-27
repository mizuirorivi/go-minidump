package main

import (
	"fmt"
	"go-minidump/pkgs/dump"
	"os"
	"strconv"
)

func usage() {
	fmt.Println("Usage: minidump <PID> <DumpFile>")
}
func main() {
	if len(os.Args) < 3 {
		usage()
		panic("[-]Error not enough arguments")
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		usage()
		panic("[-]Error converting PID to int")
	}
	DumpFile := os.Args[2]
	if DumpFile == "" {
		usage()
		panic("[-]Error DumpFile is empty")
	}
	d := dump.DumpState{
		ProcessID: pid,
		FileName:  DumpFile,
	}

	d.Run()
}
