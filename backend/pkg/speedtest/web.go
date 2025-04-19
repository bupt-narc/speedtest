package speedtest

import (
	"crypto/tls"
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/go-chi/render"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	randomData []byte
)

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func ListenAndServe() error {
	log := logrus.WithFields(logrus.Fields{
		"func": "startListener",
	})

	randomData = getRandomData(log, ChunkSize)

	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.GetHead)

	// 从环境变量读取 CORS 允许的域名
	frontendDomain := os.Getenv("FRONTEND_DOMAIN")
	if frontendDomain == "" {
		frontendDomain = "*"
	}
	cs := cors.New(cors.Options{
		AllowedOrigins: []string{frontendDomain},
		AllowedMethods: []string{"GET", "POST", "OPTIONS", "HEAD"},
		AllowedHeaders: []string{"*"},
	})

	r.Use(cs.Handler)
	r.Use(middleware.NoCache)
	r.Use(middleware.Recoverer)
	// 定义测速 API 路由
	// 替换 options.BaseURL 为环境变量读取：
	basePath := os.Getenv("API_BASE_PATH")
	if basePath == "" {
	    basePath = "/" // 默认根路径
	}
	// 修改所有路由注册代码（原 options.BaseURL 替换为 basePath）：
	r.HandleFunc(basePath+"/empty", empty)
	r.HandleFunc(basePath+"/backend/empty", empty)
	r.Get(basePath+"/garbage", garbage)
	r.Get(basePath+"/backend/garbage", garbage)
	r.Get(basePath+"/getIP", getIP)
	r.Get(basePath+"/backend/getIP", getIP)
	// 兼容 PHP 旧路径
	r.HandleFunc(basePath+"/empty.php", empty)
	r.HandleFunc(basePath+"/backend/empty.php", empty)
	r.Get(basePath+"/garbage.php", garbage)
	r.Get(basePath+"/backend/garbage.php", garbage)
	r.Get(basePath+"/getIP.php", getIP)
	r.Get(basePath+"/backend/getIP.php", getIP)

	return startListener(r)
}

func startListener(r *chi.Mux) error {
	var s error
	log := logrus.WithFields(logrus.Fields{
		"func": "startListener",
	})

	addr := net.JoinHostPort(options.BindAddress, strconv.Itoa(options.Port))
	log.Infof("Starting backend server on %s", addr)

	if options.EnableTLS {
		log.Info("Use TLS connection.")
		if !(options.EnableHTTP2) {
			srv := &http.Server{
				Addr:              addr,
				Handler:           r,
				ReadHeaderTimeout: DefaultHTTPTimeout,
				TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
			}
			s = srv.ListenAndServeTLS(options.TLSCertFile, options.TLSKeyFile)
		} else {
			srv := &http.Server{
				Addr:              addr,
				Handler:           r,
				ReadHeaderTimeout: DefaultHTTPTimeout,
			}
			s = srv.ListenAndServeTLS(options.TLSCertFile, options.TLSKeyFile)
		}
	} else {
		if options.EnableHTTP2 {
			log.Errorf("TLS is mandatory for HTTP/2. Ignore settings that enable HTTP/2.")
		}
		srv := &http.Server{
			Addr:              addr,
			Handler:           r,
			ReadHeaderTimeout: DefaultHTTPTimeout,
		}
		s = srv.ListenAndServe()
	}

	return s
}

func empty(w http.ResponseWriter, r *http.Request) {
	_, err := io.Copy(io.Discard, r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
}

func garbage(w http.ResponseWriter, r *http.Request) {
	log := logrus.WithFields(logrus.Fields{
		"func": "garbage",
	})

	w.Header().Set("Content-Description", "File Transfer")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=random.dat")
	w.Header().Set("Content-Transfer-Encoding", "binary")

	chunks := 4
	i, err := strconv.ParseInt(r.FormValue("ckSize"), 10, 64)
	switch {
	case err != nil:
		log.Debugf("Invalid param ckSize, using the default size: 4")
	case i > MaxChunkSize:
		log.Warnf("Invalid param ckSize: %d, using max chunk size: %d instead.",
			i, MaxChunkSize)
		chunks = MaxChunkSize
	default:
		chunks = int(i)
	}

	for i := 0; i < chunks; i++ {
		if _, err := w.Write(randomData); err != nil {
			log.Errorf("Error writing back to client at chunk number %d: %s", i, err)
			break
		}
	}
}

type Result struct {
	ProcessedString string `json:"processedString"`
}

func getIP(w http.ResponseWriter, r *http.Request) {
	var ret Result
	log := logrus.WithFields(logrus.Fields{
		"func": "getIP",
	})

	clientIP := r.RemoteAddr
	clientIP = strings.ReplaceAll(clientIP, "::ffff:", "")

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		clientIP = ip
	}

	isSpecialIP := true
	switch {
	case clientIP == "::1":
		ret.ProcessedString = clientIP + " - localhost IPv6 access"
	case strings.HasPrefix(clientIP, "fe80:"):
		ret.ProcessedString = clientIP + " - link-local IPv6 access"
	case strings.HasPrefix(clientIP, "127."):
		ret.ProcessedString = clientIP + " - localhost IPv4 access"
	case strings.HasPrefix(clientIP, "10."):
		ret.ProcessedString = clientIP + " - private IPv4 access"
	case regexp.MustCompile(`^172\.(1[6-9]|2\d|3[01])\.`).MatchString(clientIP):
		ret.ProcessedString = clientIP + " - private IPv4 access"
	case strings.HasPrefix(clientIP, "192.168"):
		ret.ProcessedString = clientIP + " - private IPv4 access"
	case strings.HasPrefix(clientIP, "169.254"):
		ret.ProcessedString = clientIP + " - link-local IPv4 access"
	case regexp.MustCompile(`^100\.([6-9][0-9]|1[0-2][0-7])\.`).MatchString(clientIP):
		ret.ProcessedString = clientIP + " - CGNAT IPv4 access"
	default:
		isSpecialIP = false
	}

	if isSpecialIP {
		b, _ := json.Marshal(&ret)
		if _, err := w.Write(b); err != nil {
			log.Errorf("Error writing to client: %s", err)
		}
		return
	}

	ret.ProcessedString = clientIP
	render.JSON(w, r, ret)
}
