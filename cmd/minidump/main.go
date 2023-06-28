package main

import (
	"fmt"
	"go-minidump/pkgs/dump"
	pasrses "go-minidump/pkgs/parses"
)

func usage() {
	fmt.Println("Usage: minidump <PID> <DumpFile>")
}
func main() {
	f := pasrses.Parse()
	d := dump.DumperState{
		ProcessID:   f.ProcessID,
		FileName:    f.FileName,
		ProcessName: f.ProcessName,
	}

	err := d.Dump()
	if err != nil {
		panic(err)
	}
}
