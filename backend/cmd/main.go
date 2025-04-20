package main

import (
	"github.com/yarqwq/speedtest/pkg/core"
	"os"
)

func main() {
	err := speedtest.NewCommand().Execute()

	if err != nil {
		os.Exit(1)
	}
}
