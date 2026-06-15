package portal

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/response"
)

// SSE event channel for the portal. Pushes notifications when admin
// actions invalidate the user's view — e.g. access policy mutated,
// tenant updated — so the UI can re-fetch without the user reloading.
//
// One connection per portal tab. Lifetime tied to the HTTP request;
// EventSource on the browser auto-reconnects on disconnect.
//
// Event types emitted by this endpoint (client switches on SSE `event:`):
//   apps_updated     — re-fetch /apps list
//   tenants_updated  — re-fetch /tenants list
//   ping             — heartbeat every 25s to keep proxies open
type eventsHandler struct {
	bus *event.Bus
}

// global broadcaster — single set of channels that the bus subscribers
// fan events out to. Per-SSE-connection channels register themselves
// here on connect and unregister on disconnect.
var sseBroker = newBroker()

// brokerEvent is what the bus subscribers push into SSE connections.
type brokerEvent struct {
	Type    string `json:"type"`
	Payload any    `json:"payload,omitempty"`
}

type broker struct {
	subs map[chan brokerEvent]struct{}
	add  chan chan brokerEvent
	del  chan chan brokerEvent
	pub  chan brokerEvent
}

func newBroker() *broker {
	b := &broker{
		subs: map[chan brokerEvent]struct{}{},
		add:  make(chan chan brokerEvent),
		del:  make(chan chan brokerEvent),
		pub:  make(chan brokerEvent, 64),
	}
	go b.run()
	return b
}

func (b *broker) run() {
	for {
		select {
		case ch := <-b.add:
			b.subs[ch] = struct{}{}
		case ch := <-b.del:
			delete(b.subs, ch)
			close(ch)
		case ev := <-b.pub:
			for ch := range b.subs {
				select {
				case ch <- ev:
				default:
					// Slow subscriber — drop instead of stalling broker.
				}
			}
		}
	}
}

func (b *broker) subscribe() chan brokerEvent {
	ch := make(chan brokerEvent, 32)
	b.add <- ch
	return ch
}

func (b *broker) unsubscribe(ch chan brokerEvent) {
	b.del <- ch
}

// AttachBusSubscribers wires the in-process event bus to the SSE broker.
// Called once at bootstrap from portal.Register so events emitted by any
// domain module (access policy, tenant, etc) reach connected portal SPAs.
func AttachBusSubscribers(bus *event.Bus) {
	bus.Subscribe("app_access.changed", func(ctx context.Context, e event.Event) {
		_ = ctx
		sseBroker.pub <- brokerEvent{Type: "apps_updated", Payload: e.Payload}
	})
	bus.Subscribe("tenant.updated", func(ctx context.Context, e event.Event) {
		_ = ctx
		sseBroker.pub <- brokerEvent{Type: "tenants_updated"}
	})
	bus.Subscribe("tenant.deleted", func(ctx context.Context, e event.Event) {
		_ = ctx
		sseBroker.pub <- brokerEvent{Type: "tenants_updated"}
	})
}

func registerEventsRoutes(rg *gin.RouterGroup, h *eventsHandler) {
	rg.GET("/events", h.stream)
}

func (h *eventsHandler) stream(c *gin.Context) {
	userID, ok := authn.GetUserID(c)
	if !ok {
		response.Unauthorized(c, 40101, "not authenticated")
		return
	}

	ch := sseBroker.subscribe()
	defer sseBroker.unsubscribe(ch)

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no")
	c.Writer.WriteHeader(200)
	c.Writer.Flush()

	writeSSE(c, "hello", map[string]any{"user_id": strconv.FormatInt(userID, 10)})

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	ctx := c.Request.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !writeSSE(c, "ping", nil) {
				return
			}
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if !writeSSE(c, ev.Type, ev.Payload) {
				return
			}
		}
	}
}

func writeSSE(c *gin.Context, eventName string, payload any) bool {
	w := c.Writer
	if _, err := fmt.Fprintf(w, "event: %s\n", eventName); err != nil {
		return false
	}
	if payload != nil {
		bs, _ := json.Marshal(payload)
		if _, err := fmt.Fprintf(w, "data: %s\n\n", string(bs)); err != nil {
			return false
		}
	} else {
		if _, err := fmt.Fprint(w, "data: {}\n\n"); err != nil {
			return false
		}
	}
	w.Flush()
	return true
}
