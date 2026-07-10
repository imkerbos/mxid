// Package metrics exposes Prometheus RED metrics + the standard Go/process
// collectors on a private registry, plus a Gin middleware and /metrics handler.
// The endpoint is meant for internal scraping only — the deployment (nginx)
// must not expose /metrics publicly.
package metrics

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	reg = prometheus.NewRegistry()

	reqTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mxid_http_requests_total",
		Help: "Total HTTP requests, by method, matched route and status.",
	}, []string{"method", "route", "status"})

	reqDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "mxid_http_request_duration_seconds",
		Help:    "HTTP request latency in seconds, by method and matched route.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route"})

	buildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxid_build_info",
		Help: "Build info; the value is always 1.",
	}, []string{"version"})

	// Background-worker health: run counter + last-success timestamp so a wedged
	// sweeper (retention / reconcile / outbox) is detectable (now - last_success).
	workerRuns = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mxid_worker_runs_total",
		Help: "Background worker pass count, by worker name.",
	}, []string{"worker"})
	workerLastSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxid_worker_last_success_timestamp_seconds",
		Help: "Unix time of the last successful pass, by worker name.",
	}, []string{"worker"})

	// Transactional outbox dispatch outcomes (success / retry / deadletter) — a
	// rising deadletter rate means a poisoned side-effect (e.g. a stuck webhook).
	outboxDispatch = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mxid_outbox_dispatch_total",
		Help: "Outbox message dispatch outcomes.",
	}, []string{"result"})

	// dlock leadership: 1 when this replica currently holds the advisory lock for
	// a key, else 0 — lets an operator see which pod runs each singleton job.
	dlockLeader = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxid_dlock_leader",
		Help: "1 if this replica holds the dlock advisory lock for the key.",
	}, []string{"key"})

	// authz binding-cache outcomes (l1 hit / l2 hit / miss) — hit-rate tells you
	// whether the cache is effective before a decision touches the DB.
	authzCache = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mxid_authz_cache_total",
		Help: "authz binding-cache lookups, by result.",
	}, []string{"result"})
)

func init() {
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	reg.MustRegister(reqTotal, reqDuration, buildInfo, workerRuns, workerLastSuccess, outboxDispatch, dlockLeader, authzCache)
}

// WorkerRun records that a background worker completed a pass; WorkerSuccess
// additionally stamps the last-success time. Call WorkerRun every pass and
// WorkerSuccess only when the pass did its job without error.
func WorkerRun(worker string)     { workerRuns.WithLabelValues(worker).Inc() }
func WorkerSuccess(worker string) { workerLastSuccess.WithLabelValues(worker).SetToCurrentTime() }

// OutboxDispatch records one dispatch outcome: "success", "retry" or "deadletter".
func OutboxDispatch(result string) { outboxDispatch.WithLabelValues(result).Inc() }

// DlockLeader reflects whether this replica currently holds the advisory lock.
func DlockLeader(key string, held bool) {
	v := 0.0
	if held {
		v = 1
	}
	dlockLeader.WithLabelValues(key).Set(v)
}

// AuthzCache records a binding-cache lookup outcome: "l1", "l2" or "miss".
func AuthzCache(result string) { authzCache.WithLabelValues(result).Inc() }

// SetBuildInfo records a single mxid_build_info series so a fleet-wide dashboard
// can group by running version.
func SetBuildInfo(version string) {
	buildInfo.WithLabelValues(version).Set(1)
}

// Handler serves the private registry at /metrics.
func Handler() gin.HandlerFunc {
	h := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	return func(c *gin.Context) { h.ServeHTTP(c.Writer, c.Request) }
}

// Middleware records RED metrics per request. The route label is the REGISTERED
// path pattern (c.FullPath(), e.g. /api/v1/console/users/:id), not the raw URL,
// so path parameters can't explode label cardinality. Unmatched routes collapse
// to a single "unmatched" series.
func Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		reqDuration.WithLabelValues(c.Request.Method, route).Observe(time.Since(start).Seconds())
		reqTotal.WithLabelValues(c.Request.Method, route, strconv.Itoa(c.Writer.Status())).Inc()
	}
}
