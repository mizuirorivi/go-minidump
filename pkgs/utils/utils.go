package utils

import (
	"fmt"
	"os"
	"path/filepath"
)

func FindDLL(name string) (string, error) {
	if name == "comsvc.dll" {
		return filepath.Join(os.Getenv("WINDIR"), "System32", name), nil
	}
	return "", fmt.Errorf("[-]Error finding DLL: %s", name)
}
func FindFile(name string) (string, error) {
	return "", nil
}
