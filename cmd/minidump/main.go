package main

import (
	"go-minidump/pkgs/dump"
	pasrses "go-minidump/pkgs/parses"
)

func main() {
	f := pasrses.Parse()
	d := dump.DumperState{
		ProcessID:   f.ProcessID,
		FileName:    f.FileName,
		ProcessName: f.ProcessName,
		Option:      dump.FunctionOption(f.Option),
	}

	err := d.Dump()
	if err != nil {
		panic(err)
	}
}
