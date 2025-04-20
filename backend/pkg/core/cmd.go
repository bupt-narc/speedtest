package speedtest

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	defaultLogLevel    = "info"
	defaultBindAddress = "0.0.0.0"
	defaultPort        = 80
	defaultBaseURL     = ""
	defaultEnableHTTP2 = false
	defaultEnableTLS   = false
)

const (
	flagLogLevel      = "log-level"
	flagLogLevelUsage = "Log level"

	flagBindAddress      = "bind-address"
	flagBindAddressUsage = "Bind address"

	flagPort      = "port"
	flagPortUsage = "Listen port"

	flagBaseURL      = "base-url"
	flagBaseURLUsage = "Base url"

	flagHTTP2      = "http2"
	flagHTTP2Usage = "Enable HTTP/2"

	flagTLSCertFile      = "cert-file"
	flagTLSCertFileUsage = "Certificate file for HTTPS"

	flagTLSKeyFile      = "key-file"
	flagTLSKeyFileUsage = "Certificate file for HTTPS"
)

const commandLongHelp = "Speed test for test speed."

func NewCommand() *cobra.Command {
	c := &cobra.Command{
		Use:          "ingress",
		Long:         commandLongHelp,
		SilenceUsage: true,
		RunE:         runCli,
	}
	addFlags(c.Flags())
	c.AddCommand(NewVersionCommand())
	return c
}

func NewVersionCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "version",
		Short: "show pdd-speedtest version and exit",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("0.0.1")
		},
	}
	return c
}

func addFlags(f *pflag.FlagSet) {
	f.String(flagLogLevel, defaultLogLevel, flagLogLevelUsage)
	f.String(flagBindAddress, defaultBindAddress, flagBindAddressUsage)
	f.Int(flagPort, defaultPort, flagPortUsage)
	f.String(flagBaseURL, defaultBaseURL, flagBaseURLUsage)
	f.Bool(flagHTTP2, defaultEnableHTTP2, flagHTTP2Usage)
	f.String(flagTLSCertFile, "", flagTLSCertFileUsage)
	f.String(flagTLSKeyFile, "", flagTLSKeyFileUsage)
}
