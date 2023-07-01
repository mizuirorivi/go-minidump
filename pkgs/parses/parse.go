package pasrses

import (
	"flag"
)

type Flag struct {
	FileName    string
	ProcessID   int
	ProcessName string
	Option      int
}

func Parse() *Flag {

	f := &Flag{}
	flag.StringVar(&f.FileName, "f", "", "File name to dump")
	flag.IntVar(&f.ProcessID, "p", 0, "Process ID to dump")
	flag.StringVar(&f.ProcessName, "n", "lsass.exe", "Process name to dump")
	flag.IntVar(&f.Option, "o", 0, "Dump option:\n"+
		"0: MiniDumpWriteDump\n"+
		"1: PssCaptureSnapshot",
	)
	flag.Parse()
	return f
}
