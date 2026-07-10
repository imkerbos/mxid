package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// A served request must be counted with the REGISTERED route pattern (not the
// concrete path), and the /metrics handler must expose it alongside the Go
// runtime collectors.
func TestMiddlewareRecordsRedAndExposesMetrics(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(Middleware())
	r.GET("/api/v1/console/users/:id", func(c *gin.Context) { c.Status(http.StatusOK) })

	// Drive a request through the instrumented route.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/console/users/42", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("route status = %d", w.Code)
	}

	// Scrape /metrics.
	mw := httptest.NewRecorder()
	Handler()(func() *gin.Context { c, _ := gin.CreateTestContext(mw); c.Request = httptest.NewRequest("GET", "/metrics", nil); return c }())
	body := mw.Body.String()

	// RED counter present, labelled by the pattern (path param collapsed).
	if !strings.Contains(body, `mxid_http_requests_total{method="GET",route="/api/v1/console/users/:id",status="200"}`) {
		t.Fatalf("request counter missing/mis-labelled:\n%s", firstLines(body, 40))
	}
	if !strings.Contains(body, "mxid_http_request_duration_seconds") {
		t.Fatal("duration histogram missing")
	}
	// Go runtime + process collectors registered.
	if !strings.Contains(body, "go_goroutines") {
		t.Fatal("go collector missing")
	}
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
