package speedtest

import (
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	options *Option
)

func runCli(cmd *cobra.Command, _ []string) error {
	var err error
	options, err = NewOption().
		WithDefaults().
		WithCliFlags(cmd.Flags()).
		Validate()
	if err != nil {
		return errors.Wrap(err, "error when parsing flags")
	}

	level, _ := logrus.ParseLevel(options.LogLevel)
	logrus.SetLevel(level)
	logrus.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: "15:04:05.000",
		FullTimestamp:   true,
	})

	err = ListenAndServe()
	return err
}
