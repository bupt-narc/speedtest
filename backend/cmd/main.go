package main

import (
	"github.com/bupt-narc/speedtest/pkg/core"
	"os"
)

func main() {
	err := speedtest.NewCommand().Execute()

	if err != nil {
		os.Exit(1)
	}
}
