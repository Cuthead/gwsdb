package web

import (
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

// Response compression. The home page's HTML table is large (roughly 500
// bytes per tracked IP) and highly repetitive, so compressing it cuts the
// transfer to a small fraction. zstd is preferred when the client advertises
// it, with gzip as the fallback for browsers that don't (notably Safari).

// zstdPool and gzipPool reuse encoders across responses; a fresh zstd
// encoder allocates large internal buffers, so per-request construction
// would dominate the cost of compressing these small pages.
var zstdPool = sync.Pool{New: func() any {
	// The default options never fail; concurrency 1 keeps the encoder from
	// spawning per-CPU goroutines that a single HTML page can't use.
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		panic(err)
	}
	return enc
}}

var gzipPool = sync.Pool{New: func() any { return gzip.NewWriter(nil) }}

// acceptsEncoding reports whether the request's Accept-Encoding header lists
// enc with a non-zero quality value.
func acceptsEncoding(r *http.Request, enc string) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(name), enc) {
			continue
		}
		if v, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			if q, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && q == 0 {
				return false
			}
		}
		return true
	}
	return false
}

// compressibleType reports whether a response Content-Type is worth
// compressing. The flag GIFs are already compressed; everything else this
// server emits (HTML, CSS, JS) is text.
func compressibleType(ct string) bool {
	return strings.HasPrefix(ct, "text/") || strings.Contains(ct, "javascript")
}

// compressWriter wraps a ResponseWriter and, once the status and headers are
// known, transparently encodes the body when the response is a compressible
// 200. Anything else (errors, redirects, 206 ranges, images) passes through
// untouched.
type compressWriter struct {
	http.ResponseWriter
	encoding    string // negotiated: "zstd" or "gzip"
	zenc        *zstd.Encoder
	genc        *gzip.Writer
	wroteHeader bool
}

func (cw *compressWriter) WriteHeader(code int) {
	if cw.wroteHeader {
		return
	}
	cw.wroteHeader = true
	h := cw.Header()
	if code == http.StatusOK && h.Get("Content-Encoding") == "" && compressibleType(h.Get("Content-Type")) {
		// The body length changes under compression, so the pre-computed
		// Content-Length (set by e.g. http.FileServer) must go.
		h.Del("Content-Length")
		h.Set("Content-Encoding", cw.encoding)
		switch cw.encoding {
		case "zstd":
			cw.zenc = zstdPool.Get().(*zstd.Encoder)
			cw.zenc.Reset(cw.ResponseWriter)
		case "gzip":
			cw.genc = gzipPool.Get().(*gzip.Writer)
			cw.genc.Reset(cw.ResponseWriter)
		}
	}
	cw.ResponseWriter.WriteHeader(code)
}

func (cw *compressWriter) Write(p []byte) (int, error) {
	if !cw.wroteHeader {
		cw.WriteHeader(http.StatusOK)
	}
	switch {
	case cw.zenc != nil:
		return cw.zenc.Write(p)
	case cw.genc != nil:
		return cw.genc.Write(p)
	}
	return cw.ResponseWriter.Write(p)
}

// close flushes the encoder's trailing frame and returns it to its pool.
func (cw *compressWriter) close() {
	switch {
	case cw.zenc != nil:
		cw.zenc.Close()
		zstdPool.Put(cw.zenc)
	case cw.genc != nil:
		cw.genc.Close()
		gzipPool.Put(cw.genc)
	}
}

// compressResponses negotiates a Content-Encoding for each request and
// wraps the ResponseWriter accordingly.
func compressResponses(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set on every response, compressed or not, so a shared cache never
		// serves an encoded body to a client that didn't ask for it.
		w.Header().Add("Vary", "Accept-Encoding")
		var encoding string
		switch {
		case acceptsEncoding(r, "zstd"):
			encoding = "zstd"
		case acceptsEncoding(r, "gzip"):
			encoding = "gzip"
		default:
			next.ServeHTTP(w, r)
			return
		}
		cw := &compressWriter{ResponseWriter: w, encoding: encoding}
		defer cw.close()
		next.ServeHTTP(cw, r)
	})
}
