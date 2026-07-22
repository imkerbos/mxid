package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/domain/upload"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/snowflake"
)

// errIconRejected wraps the operator-fixable saveIcon failures (too large,
// unsupported type). The handler 400s on it and routes every OTHER saveIcon
// error (a wrapped io/DB failure) to a logged 500 rather than echoing the infra
// error text back to the client.
var errIconRejected = errors.New("icon rejected")

// Uploaded assets live in the database (see internal/domain/upload), NOT on
// local disk — so the backend keeps no local file state. The serve path reads
// straight from the row and strong-caches it.

const (
	// 2 MB ceiling. App icons / brand logos are small; this comfortably covers a
	// high-res PNG/JPG logo while still rejecting accidental full-size photos.
	// nginx client_max_body_size (50m) is well above this.
	maxIconBytes = 2 * 1024 * 1024

	iconCategory = "app-icon"
	// iconPrefix is the public URL prefix. Kept identical to the legacy on-disk
	// layout so existing app.icon / branding.logo_url values keep their shape.
	iconPrefix = "/static/app-icons/"
)

// allowedIconMime caps the accepted formats. SVG is accepted but treated as
// hostile input: it can embed <script>, and icons are served same-origin and
// unauthenticated. The serve path neutralises this with X-Content-Type-Options:
// nosniff + a CSP sandbox (no allow-scripts), so a scripted SVG can neither run
// on direct navigation nor be re-sniffed as HTML; saveIcon additionally sniffs
// the bytes (see looksLikeSVG) so the svg+xml Content-Type can't smuggle an HTML
// document. Rejecting unknown types also keeps users from uploading PDFs or
// HEIC that don't render.
var allowedIconMime = map[string]string{
	"image/png":     ".png",
	"image/jpeg":    ".jpg",
	"image/webp":    ".webp",
	"image/gif":     ".gif",
	"image/svg+xml": ".svg",
}

// RegisterUpload wires the icon upload endpoint and the DB-backed static serve.
// Assets live in the database, so there are no local files: no PVC under k8s,
// icons survive restarts under docker, and every replica serves identical bytes.
func RegisterUpload(r *gin.Engine, consoleGroup *gin.RouterGroup, idGen *snowflake.Generator, repo upload.Repository) error {
	// Serve: GET /static/app-icons/<id>.<ext>. The <ext> is cosmetic (the real
	// content-type comes from the row); only the id is parsed. Root-level + no
	// auth: login pages fetch icons via <img> with no cookie.
	r.GET(iconPrefix+":name", func(c *gin.Context) {
		id := parseIconID(c.Param("name"))
		if id == 0 {
			c.Status(http.StatusNotFound)
			return
		}
		// Immutable: a new upload always mints a new id, so a given URL's bytes
		// never change. Cache hard (1 year, immutable) and honour revalidation
		// before touching the DB.
		etag := `"` + strconv.FormatInt(id, 10) + `"`
		if c.GetHeader("If-None-Match") == etag {
			c.Status(http.StatusNotModified)
			return
		}
		u, err := repo.Get(c.Request.Context(), id)
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		c.Header("Cache-Control", "public, max-age=31536000, immutable")
		c.Header("ETag", etag)
		// Defense-in-depth for the unauthenticated same-origin asset serve:
		// never let the browser sniff a different type, and sandbox/deny any
		// active content if the URL is navigated to directly.
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Content-Security-Policy", "default-src 'none'; sandbox")
		c.Data(http.StatusOK, u.Mime, u.Data)
	})

	// Icon upload is part of app authoring — used by both the create and edit
	// forms (no app id exists yet at create time), so allow either app.create
	// or app.update. RequireAny does the RBAC check; the matching entry in
	// consoleProtectedRoutes registers it with the deny-by-default gateway.
	consoleGroup.POST("/upload/app-icon", authz.RequireAny([]string{"app.create", "app.update"}, nil), func(c *gin.Context) {
		f, header, err := c.Request.FormFile("file")
		if err != nil {
			response.BadRequest(c, 40001, "file field required")
			return
		}
		defer f.Close()

		url, err := saveIcon(c.Request.Context(), f, header, repo, idGen)
		if err != nil {
			if errors.Is(err, errIconRejected) {
				response.BadRequest(c, 40002, err.Error())
				return
			}
			response.InternalError(c, "failed to save icon", err)
			return
		}
		response.OK(c, gin.H{"url": url})
	})

	return nil
}

// looksLikeSVG reports whether data is plausibly an SVG document rather than
// arbitrary markup wearing an image/svg+xml Content-Type. It skips a leading
// UTF-8 BOM and whitespace, requires the content to open as XML/markup, and
// requires an "<svg" root element to appear early — enough to reject an HTML
// page or junk while staying lenient about an <?xml declaration, a DOCTYPE, or
// comments preceding the root.
func looksLikeSVG(data []byte) bool {
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}) // UTF-8 BOM
	data = bytes.TrimLeft(data, " \t\r\n")
	if len(data) == 0 || data[0] != '<' {
		return false
	}
	// Only look near the top; the root element comes right after any xml decl /
	// doctype / comment, well within the first kilobyte.
	head := data
	if len(head) > 1024 {
		head = head[:1024]
	}
	return bytes.Contains(bytes.ToLower(head), []byte("<svg"))
}

// parseIconID extracts the Snowflake id from "<id>.<ext>" (or a bare "<id>").
// Returns 0 on anything unparseable.
func parseIconID(name string) int64 {
	if i := strings.LastIndexByte(name, '.'); i > 0 {
		name = name[:i]
	}
	id, err := strconv.ParseInt(name, 10, 64)
	if err != nil || id <= 0 {
		return 0
	}
	return id
}

// saveIcon validates and persists an uploaded icon into the DB. Returns the
// public URL the caller stores in app.icon. Content-type is taken from the
// multipart header (caller-supplied — fine here since the endpoint is the
// trusted admin console, not anonymous).
func saveIcon(ctx context.Context, src multipart.File, header *multipart.FileHeader, repo upload.Repository, idGen *snowflake.Generator) (string, error) {
	if header.Size > maxIconBytes {
		return "", fmt.Errorf("%w: file too large: %d bytes (max %d)", errIconRejected, header.Size, maxIconBytes)
	}

	mime := strings.ToLower(header.Header.Get("Content-Type"))
	// Some browsers attach charset to svg+xml — trim it.
	if i := strings.Index(mime, ";"); i > 0 {
		mime = strings.TrimSpace(mime[:i])
	}
	ext, ok := allowedIconMime[mime]
	if !ok {
		return "", fmt.Errorf("%w: unsupported content-type: %s", errIconRejected, mime)
	}

	// Read into memory with a hard cap (+1 to detect a lying Content-Length that
	// claims <= max but streams more).
	data, err := io.ReadAll(io.LimitReader(src, maxIconBytes+1))
	if err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}
	if len(data) > maxIconBytes {
		return "", fmt.Errorf("%w: file too large (max %d bytes)", errIconRejected, maxIconBytes)
	}

	// The svg+xml Content-Type is trivially forgeable, and unlike raster formats
	// SVG is text that could just as well be an HTML document. Sniff the actual
	// bytes so an svg+xml upload really is an SVG root, not smuggled markup.
	if mime == "image/svg+xml" && !looksLikeSVG(data) {
		return "", fmt.Errorf("%w: file is not a valid SVG document", errIconRejected)
	}

	id := idGen.Generate()
	if err := repo.Save(ctx, &upload.Upload{
		ID:       id,
		Category: iconCategory,
		Mime:     mime,
		Ext:      ext,
		Size:     len(data),
		Data:     data,
	}); err != nil {
		return "", fmt.Errorf("save upload: %w", err)
	}

	return fmt.Sprintf("%s%d%s", iconPrefix, id, ext), nil
}
