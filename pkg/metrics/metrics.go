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

	// External-IdP round trips, by provider and phase ("start" / "callback").
	// A start that never reaches callback means the browser left for the provider
	// and never came back — the provider's own login page failed, which we cannot
	// observe any other way (that request never touches us; Lark served a bare
	// 502 from its accounts host and the user read it as our outage).
	//
	// Alert on the gap, not on an error rate: rate(start) - rate(callback)
	// staying above ~0 for a few minutes means the provider is broken. Some gap
	// is normal — people abandon a login — so alert on a sustained ratio, not on
	// a single missing pair.
	extLoginPhase = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mxid_external_login_phase_total",
		Help: "External-IdP login round trips, by provider and phase.",
	}, []string{"provider", "phase"})

	// Token-endpoint rejections, by OAuth error code. Deliberately NOT labelled
	// by client_id: the client_id on a token request is whatever the caller
	// asserted, so an attacker could mint a new label value per attempt and turn
	// this counter into unbounded cardinality. The error code comes from our own
	// engine and is a closed set, and oidcErrorLabel folds anything unexpected
	// into "other" so that stays true. Per-client detail belongs in the audit
	// event, which is bounded by storage rather than by series count.
	oidcGrantRejected = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mxid_oidc_grant_rejected_total",
		Help: "Rejected OIDC token-endpoint exchanges, by OAuth error code.",
	}, []string{"error"})

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

	// Audit writes that were lost. The action happened but left no trail, and
	// the request still succeeded — so this counter is the ONLY signal. Alert
	// on any increase.
	auditWriteFailed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mxid_audit_write_failed_total",
		Help: "Audit log writes that failed. Non-zero means audit trail loss.",
	}, []string{"reason"})

	// Audit records mirrored to an external collector, by outcome: "sent",
	// "dropped" (the forwarding queue was full) or "failed" (the collector
	// refused or was unreachable). The database still holds every record, so
	// this measures the completeness of the OFF-HOST copy — the one that
	// survives someone with database access deciding history is inconvenient.
	// Alert on dropped or failed climbing.
	auditForward = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mxid_audit_forward_total",
		Help: "Audit records mirrored off-host, by outcome (sent/dropped/failed).",
	}, []string{"result"})

	// Provisioned future partitions for a time-partitioned table. When this
	// reaches 0 the table is one month from rejecting every insert.
	partitionsAhead = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxid_partitions_ahead",
		Help: "Future monthly partitions provisioned beyond the current month.",
	}, []string{"table"})

	// Rows sitting in a DEFAULT backstop partition. Zero is the only healthy
	// value: anything else means pre-creation fell behind AND that the affected
	// month's partition can no longer be created until the rows are adopted.
	partitionDefaultRows = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxid_partition_default_rows",
		Help: "Rows in the DEFAULT partition. Must be 0; non-zero wedges partition creation.",
	}, []string{"table"})

	// Partitions dropped by retention, so an operator can see retention is
	// actually reclaiming space rather than silently doing nothing.
	partitionsDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mxid_partitions_dropped_total",
		Help: "Partitions dropped by retention.",
	}, []string{"table"})

	// Depth of the audit capture queue. The chainer is a single leader-elected
	// writer, so if it stops or falls behind, this grows without bound and
	// nothing else reports it — the captures themselves keep succeeding.
	auditPendingDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mxid_audit_pending_depth",
		Help: "Rows waiting in mxid_audit_pending. Sustained growth means the chainer is stalled.",
	})

	// How far the anchorer trails the chain tail, per chain. Entries are only
	// verifiable as a range once anchored, so a growing lag is a growing window
	// of history that cannot be proven intact.
	auditAnchorLag = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxid_audit_anchor_lag",
		Help: "Chain entries written but not yet anchored, by tenant and chain class.",
	}, []string{"tenant", "chain_class"})
)

func init() {
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	reg.MustRegister(reqTotal, reqDuration, buildInfo, workerRuns, workerLastSuccess, outboxDispatch, dlockLeader, authzCache,
		auditWriteFailed, auditForward, partitionsAhead, partitionDefaultRows, partitionsDropped,
		auditPendingDepth, auditAnchorLag, extLoginPhase, oidcGrantRejected)
}

// WorkerRun records that a background worker completed a pass; WorkerSuccess
// additionally stamps the last-success time. Call WorkerRun every pass and
// WorkerSuccess only when the pass did its job without error.
func WorkerRun(worker string)     { workerRuns.WithLabelValues(worker).Inc() }
func WorkerSuccess(worker string) { workerLastSuccess.WithLabelValues(worker).SetToCurrentTime() }

// knownOIDCErrors is the closed set of OAuth/OIDC error codes this IdP emits
// (RFC 6749 §5.2, RFC 8628 §3.5 for slow_down). It exists purely to bound the
// metric's label values — see the comment on oidcGrantRejected.
var knownOIDCErrors = map[string]struct{}{
	"invalid_request":         {},
	"invalid_client":          {},
	"invalid_grant":           {},
	"unauthorized_client":     {},
	"unsupported_grant_type":  {},
	"invalid_scope":           {},
	"slow_down":               {},
	"server_error":            {},
	"temporarily_unavailable": {},
	"invalid_target":          {},
	"invalid_dpop_proof":      {},
	"unsupported_token_type":  {},
}

// OIDCGrantRejected records one rejected token exchange. An unrecognised or
// missing code is folded into "other"/"unknown" so the label set stays closed.
func OIDCGrantRejected(oauthError string) {
	oidcGrantRejected.WithLabelValues(oidcErrorLabel(oauthError)).Inc()
}

func oidcErrorLabel(oauthError string) string {
	if oauthError == "" {
		return "unknown"
	}
	if _, ok := knownOIDCErrors[oauthError]; ok {
		return oauthError
	}
	return "other"
}

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

// ExternalLoginPhase records one leg of a federated login: phase "start" when we
// redirect to the provider, "callback" when the browser comes back. The
// difference is the provider failing on its own pages.
func ExternalLoginPhase(provider, phase string) {
	extLoginPhase.WithLabelValues(provider, phase).Inc()
}

// AuditWriteFailed records an audit entry that could not be persisted. The
// originating request has already committed and returned 200, so nothing else
// reports this — treat any non-zero value as an incident.
func AuditWriteFailed(reason string) { auditWriteFailed.WithLabelValues(reason).Inc() }

// AuditForward records one off-host mirror outcome: "sent", "dropped" or
// "failed".
func AuditForward(result string) { auditForward.WithLabelValues(result).Inc() }

// PartitionsAhead / PartitionDefaultRows / PartitionsDropped expose the health
// of a time-partitioned table's lifecycle. Alert on ahead == 0 (writes stop
// within a month) and on default_rows > 0 (partition creation is wedged).
func PartitionsAhead(table string, n int) { partitionsAhead.WithLabelValues(table).Set(float64(n)) }
func PartitionDefaultRows(table string, n int64) {
	partitionDefaultRows.WithLabelValues(table).Set(float64(n))
}
func PartitionsDropped(table string, n int) { partitionsDropped.WithLabelValues(table).Add(float64(n)) }

// AuditPendingDepth and AuditAnchorLag expose the two silent failure modes of
// the audit pipeline: a stalled chainer (captures still succeed, so nothing
// else notices) and an anchorer falling behind (history accumulates that cannot
// yet be proven intact as a range).
func AuditPendingDepth(n int64) { auditPendingDepth.Set(float64(n)) }
func AuditAnchorLag(tenant, chainClass string, n int64) {
	auditAnchorLag.WithLabelValues(tenant, chainClass).Set(float64(n))
}

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
