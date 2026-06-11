package bootstrap

import (
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/snowflake"
)

// Uploads are stored on local disk under <data_dir>/uploads/<category>/.
// Production should swap this for S3 / OSS — see UploadStorage interface
// once that's needed. For now single-node deploys are the target.

const (
	// 200KB ceiling. App icons are tiny by nature; bigger uploads here would
	// usually mean the user picked the wrong file (full screenshot etc).
	maxIconBytes = 200 * 1024

	// Subdirectory for app icons under the upload root. Kept short so the
	// URL path stays readable.
	iconSubdir = "app-icons"
)

// allowedIconMime caps the accepted formats. svg+xml is included because
// many open-source brands ship logos as SVG; everything else is raster.
// Rejecting unknown types keeps users from uploading PDFs or HEIC images
// that don't render in browsers.
var allowedIconMime = map[string]string{
	"image/png":     ".png",
	"image/jpeg":    ".jpg",
	"image/svg+xml": ".svg",
	"image/webp":    ".webp",
	"image/gif":     ".gif",
}

// RegisterUpload wires the upload endpoint and the static file server for
// previously uploaded assets. The static route is registered at the root
// engine level so it bypasses console-auth middleware — icon previews are
// fetched from <img src=...> tags without cookies.
func RegisterUpload(r *gin.Engine, consoleGroup *gin.RouterGroup, idGen *snowflake.Generator, uploadDir string) error {
	iconDir := filepath.Join(uploadDir, iconSubdir)
	if err := os.MkdirAll(iconDir, 0o755); err != nil {
		return fmt.Errorf("create icon dir: %w", err)
	}

	// Static serve. URL: /static/app-icons/<filename>.<ext>
	// Cache-control is light because admins replace icons rarely; browsers
	// re-fetch fast enough that staleness is not worth solving.
	r.Static("/static/"+iconSubdir, iconDir)

	consoleGroup.POST("/upload/app-icon", func(c *gin.Context) {
		f, header, err := c.Request.FormFile("file")
		if err != nil {
			response.BadRequest(c, 40001, "file field required")
			return
		}
		defer f.Close()

		url, err := saveIcon(f, header, iconDir, idGen)
		if err != nil {
			response.BadRequest(c, 40002, err.Error())
			return
		}
		response.OK(c, gin.H{"url": url})
	})

	return nil
}

// saveIcon validates and persists an uploaded icon. Returns the public URL
// the caller should store in app.icon. Validates content-type via the
// multipart header (caller-supplied — fine here since the admin endpoint
// is trusted-user, not anonymous).
func saveIcon(src multipart.File, header *multipart.FileHeader, iconDir string, idGen *snowflake.Generator) (string, error) {
	if header.Size > maxIconBytes {
		return "", fmt.Errorf("file too large: %d bytes (max %d)", header.Size, maxIconBytes)
	}

	mime := strings.ToLower(header.Header.Get("Content-Type"))
	// Some browsers attach charset to svg+xml — trim it.
	if i := strings.Index(mime, ";"); i > 0 {
		mime = strings.TrimSpace(mime[:i])
	}
	ext, ok := allowedIconMime[mime]
	if !ok {
		return "", fmt.Errorf("unsupported content-type: %s", mime)
	}

	id := idGen.Generate()
	name := fmt.Sprintf("%d%s", id, ext)
	dst, err := os.Create(filepath.Join(iconDir, name))
	if err != nil {
		return "", fmt.Errorf("create file: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		_ = os.Remove(dst.Name())
		return "", fmt.Errorf("write file: %w", err)
	}

	return "/static/" + iconSubdir + "/" + name, nil
}

// Compile-time guard that http is used (silences staticcheck if needed).
var _ = http.StatusOK
