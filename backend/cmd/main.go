package main

import (
	"github.com/yarqwq/speedtest/pkg/speedtest"
	"os"
)

func main() {
	err := speedtest.NewCommand().Execute()

	if err != nil {
		os.Exit(1)
	}
}
