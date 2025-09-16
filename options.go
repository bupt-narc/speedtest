package speedtest

import (
	"fmt"
	"os"
	"strconv"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

type Option struct {
	LogLevel    string
	BindAddress string
	Port        int
	BaseURL     string

	EnableHTTP2 bool
	EnableTLS   bool
	TLSCertFile string
	TLSKeyFile  string
}

func NewOption() *Option {
	return &Option{}
}

func (o *Option) WithDefaults() *Option {
	o.LogLevel = defaultLogLevel
	o.BindAddress = defaultBindAddress
	o.Port = defaultPort
	o.BaseURL = defaultBaseURL
	o.EnableHTTP2 = defaultEnableHTTP2
	o.EnableTLS = defaultEnableTLS
	return o
}

func (o *Option) WithEnvironment() *Option {
	// 从环境变量读取配置，如果环境变量存在则覆盖默认值
	if envLogLevel := os.Getenv("LOG_LEVEL"); envLogLevel != "" {
		o.LogLevel = envLogLevel
	}

	if envBindAddress := os.Getenv("BIND_ADDRESS"); envBindAddress != "" {
		o.BindAddress = envBindAddress
	}

	if envPort := os.Getenv("PORT"); envPort != "" {
		if port, err := strconv.Atoi(envPort); err == nil {
			o.Port = port
		}
	}

	if envBaseURL := os.Getenv("BASE_URL"); envBaseURL != "" {
		o.BaseURL = envBaseURL
	}

	if envHTTP2 := os.Getenv("ENABLE_HTTP2"); envHTTP2 != "" {
		if http2, err := strconv.ParseBool(envHTTP2); err == nil {
			o.EnableHTTP2 = http2
		}
	}

	if envTLS := os.Getenv("ENABLE_TLS"); envTLS != "" {
		if tls, err := strconv.ParseBool(envTLS); err == nil && tls {
			o.EnableTLS = true
			if certFile := os.Getenv("TLS_CERT_FILE"); certFile != "" {
				o.TLSCertFile = certFile
			}
			if keyFile := os.Getenv("TLS_KEY_FILE"); keyFile != "" {
				o.TLSKeyFile = keyFile
			}
		}
	}

	return o
}

func (o *Option) WithCliFlags(flags *pflag.FlagSet) *Option {
	if v, err := flags.GetString(flagLogLevel); err == nil && flags.Changed(flagLogLevel) {
		o.LogLevel = v
	}

	if v, err := flags.GetString(flagBindAddress); err == nil && flags.Changed(flagBindAddress) {
		o.BindAddress = v
	}

	if v, err := flags.GetInt(flagPort); err == nil && flags.Changed(flagPort) {
		o.Port = v
	}

	if v, err := flags.GetString(flagBaseURL); err == nil && flags.Changed(flagBaseURL) {
		o.BaseURL = v
	}

	if v, err := flags.GetBool(flagHTTP2); err == nil && flags.Changed(flagHTTP2) {
		o.EnableHTTP2 = v
	}

	cert, certErr := flags.GetString(flagTLSCertFile)
	key, keyErr := flags.GetString(flagTLSKeyFile)

	if certErr == nil && keyErr == nil && flags.Changed(flagTLSCertFile) && flags.Changed(flagTLSKeyFile) {
		o.EnableTLS = true
		o.TLSCertFile = cert
		o.TLSKeyFile = key
	}

	return o
}

func (o *Option) Validate() (*Option, error) {
	_, err := logrus.ParseLevel(o.LogLevel)
	if err != nil {
		return nil, err
	}
	if o.Port < 0 || o.Port > 65535 {
		return nil, fmt.Errorf("port should be in range [0, 65535]")
	}

	return o, nil
}
