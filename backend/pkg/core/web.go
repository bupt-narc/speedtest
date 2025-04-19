package speedtest

import (
	"crypto/tls"
	"embed"
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"io"
	"io/fs"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/render"
	"github.com/sirupsen/logrus"
)

var (
	randomData []byte
)

//go:embed frontend/dist
var defaultAssets embed.FS

func ListenAndServe() error {
	log := logrus.WithFields(logrus.Fields{
		"func": "startListener",
	})

	randomData = getRandomData(log, ChunkSize)

	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.GetHead)

	cs := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS", "HEAD"},
		AllowedHeaders: []string{"*"},
	})

	r.Use(cs.Handler)
	r.Use(middleware.NoCache)
	r.Use(middleware.Recoverer)

	var assetFS http.FileSystem
	sub, err := fs.Sub(defaultAssets, "frontend/dist")
	if err != nil {
		log.Fatalf("Failed when processing default assets: %s", err)
	}
	assetFS = http.FS(sub)

	r.Get(options.BaseURL+"/*", pages(assetFS, options.BaseURL))
	r.HandleFunc(options.BaseURL+"/empty", empty)
	r.HandleFunc(options.BaseURL+"/backend/empty", empty)
	r.Get(options.BaseURL+"/garbage", garbage)
	r.Get(options.BaseURL+"/backend/garbage", garbage)
	r.Get(options.BaseURL+"/getIP", getIP)
	r.Get(options.BaseURL+"/backend/getIP", getIP)

	// PHP frontend default values compatibility
	r.HandleFunc(options.BaseURL+"/empty.php", empty)
	r.HandleFunc(options.BaseURL+"/backend/empty.php", empty)
	r.Get(options.BaseURL+"/garbage.php", garbage)
	r.Get(options.BaseURL+"/backend/garbage.php", garbage)
	r.Get(options.BaseURL+"/getIP.php", getIP)
	r.Get(options.BaseURL+"/backend/getIP.php", getIP)

	return startListener(r)
}

func startListener(r *chi.Mux) error {
	var s error
	log := logrus.WithFields(logrus.Fields{
		"func": "startListener",
	})

	addr := net.JoinHostPort(options.BindAddress, strconv.Itoa(options.Port))
	log.Infof("Starting backend server on %s", addr)

	// TLS and HTTP/2.
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

//go:generate
func pages(fs http.FileSystem, baseURL string) http.HandlerFunc {
	log := logrus.WithFields(logrus.Fields{
		"func": "pages",
	})
	var removeBaseURL *regexp.Regexp
	if baseURL != "" {
		removeBaseURL = regexp.MustCompile("^" + baseURL + "/")
	}
	fn := func(w http.ResponseWriter, r *http.Request) {
		log.Debugf("Request %s.", r.URL.Path)
		if baseURL != "" {
			r.URL.Path = removeBaseURL.ReplaceAllString(r.URL.Path, "/")
		}
		if r.RequestURI == "/" {
			r.RequestURI = "/index.html"
		}
		http.FileServer(fs).ServeHTTP(w, r)
	}

	return fn
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

	// chunk size set to 4 by default
	chunks := 4
	i, err := strconv.ParseInt(r.FormValue("ckSize"), 10, 64)
	switch {
	case err != nil:
		// 无效的请求参数chSize
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
