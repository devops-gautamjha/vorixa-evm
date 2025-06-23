package wembed

import (
	"bytes"
	"embed"
	"io/fs"
	"net/http"
	"strings"
	"time"
)

//go:embed frontend/dist/*
var embeddedFiles embed.FS

func SPAHandler() http.Handler {
	subFS, err := fs.Sub(embeddedFiles, "frontend/dist")
	if err != nil {
		panic("failed to create sub FS: " + err.Error())
	}
	fsHandler := http.FileServer(http.FS(subFS))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath := strings.TrimPrefix(r.URL.Path, "/")

		// Try to open the requested file
		_, err := subFS.Open(requestPath)
		if err != nil || requestPath == "" {
			// Fallback to index.html using embeddedFiles (not subFS)
			data, err := embeddedFiles.ReadFile("frontend/dist/index.html")
			if err != nil {
				http.Error(w, "index.html not found", http.StatusInternalServerError)
				return
			}
			http.ServeContent(w, r, "index.html", time.Now(), bytes.NewReader(data))
			return
		}

		// Serve static file
		fsHandler.ServeHTTP(w, r)
	})
}
