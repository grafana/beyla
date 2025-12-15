// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	obiotel "go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

type mockEventMetrics struct {
	createCalls []*svc.Attrs
	deleteCalls []svc.UID
	smr         *SurveyMetricsReporter
}

func newMockEventMetrics(smr *SurveyMetricsReporter) *mockEventMetrics {
	return &mockEventMetrics{
		createCalls: make([]*svc.Attrs, 0),
		deleteCalls: make([]svc.UID, 0),
		smr:         smr,
	}
}

func (m *mockEventMetrics) createEventMetrics(ctx context.Context, targetMetrics *svc.Attrs) {
	m.createCalls = append(m.createCalls, targetMetrics)
	c := m.smr.attrsFromService(targetMetrics)
	m.smr.serviceMap[targetMetrics.UID] = c
}

func (m *mockEventMetrics) deleteEventMetrics(ctx context.Context, targetUID svc.UID) {
	m.deleteCalls = append(m.deleteCalls, targetUID)
	delete(m.smr.serviceMap, targetUID)
}

func TestHandleProcessEventCreated(t *testing.T) {
	tests := []struct {
		name           string
		setup          func(*SurveyMetricsReporter, *mockEventMetrics)
		event          exec.ProcessEvent
		expectedCreate []svc.Attrs
		expectedDelete []svc.UID
		expectedMap    map[svc.UID]svc.Attrs
	}{
		{
			name: "new service - fresh start",
			setup: func(r *SurveyMetricsReporter, m *mockEventMetrics) {
				// No setup needed for fresh start
			},
			event: exec.ProcessEvent{
				Type: exec.ProcessEventCreated,
				File: &exec.FileInfo{
					Pid: 1234,
					Service: svc.Attrs{
						UID: svc.UID{
							Name:      "test-service",
							Namespace: "default",
							Instance:  "instance-1",
						},
						HostName: "test-host",
					},
				},
			},
			expectedCreate: []svc.Attrs{
				{
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "default",
						Instance:  "instance-1",
					},
					HostName: "test-host",
				},
			},
			expectedDelete: nil,
			expectedMap: map[svc.UID]svc.Attrs{
				{
					Name:      "test-service",
					Namespace: "default",
					Instance:  "instance-1",
				}: {
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "default",
						Instance:  "instance-1",
					},
					HostName: "test-host",
				},
			},
		},
		{
			name: "same service UID with updated attributes",
			setup: func(r *SurveyMetricsReporter, m *mockEventMetrics) {
				// Pre-populate service map with existing service
				uid := svc.UID{
					Name:      "test-service",
					Namespace: "default",
					Instance:  "instance-1",
				}
				r.serviceMap[uid] = r.attrsFromService(&svc.Attrs{
					UID:      uid,
					HostName: "old-host",
				})
			},
			event: exec.ProcessEvent{
				Type: exec.ProcessEventCreated,
				File: &exec.FileInfo{
					Pid: 1234,
					Service: svc.Attrs{
						UID: svc.UID{
							Name:      "test-service",
							Namespace: "default",
							Instance:  "instance-1",
						},
						HostName: "new-host",
					},
				},
			},
			expectedCreate: []svc.Attrs{
				{
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "default",
						Instance:  "instance-1",
					},
					HostName: "new-host",
				},
			},
			expectedDelete: []svc.UID{
				{
					Name:      "test-service",
					Namespace: "default",
					Instance:  "instance-1",
				},
			},
			expectedMap: map[svc.UID]svc.Attrs{
				{
					Name:      "test-service",
					Namespace: "default",
					Instance:  "instance-1",
				}: {
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "default",
						Instance:  "instance-1",
					},
					HostName: "new-host",
				},
			},
		},
		{
			name: "PID changing service (stale UID with existing attributes)",
			setup: func(r *SurveyMetricsReporter, m *mockEventMetrics) {
				// Setup: PID 1234 is already tracked with stale UID
				staleUID := svc.UID{
					Name:      "old-service",
					Namespace: "default",
					Instance:  "instance-1",
				}
				r.pidTracker.AddPID(1234, staleUID)

				// Add stale service to service map
				r.serviceMap[staleUID] = r.attrsFromService(&svc.Attrs{
					UID:      staleUID,
					HostName: "test-host",
				})
			},
			event: exec.ProcessEvent{
				Type: exec.ProcessEventCreated,
				File: &exec.FileInfo{
					Pid: 1234,
					Service: svc.Attrs{
						UID: svc.UID{
							Name:      "new-service",
							Namespace: "default",
							Instance:  "instance-1",
						},
						HostName: "test-host",
					},
				},
			},
			expectedCreate: []svc.Attrs{
				{
					UID: svc.UID{
						Name:      "new-service",
						Namespace: "default",
						Instance:  "instance-1",
					},
					HostName: "test-host",
				},
			},
			expectedDelete: []svc.UID{
				{
					Name:      "old-service",
					Namespace: "default",
					Instance:  "instance-1",
				},
			},
			expectedMap: map[svc.UID]svc.Attrs{
				{
					Name:      "new-service",
					Namespace: "default",
					Instance:  "instance-1",
				}: {
					UID: svc.UID{
						Name:      "new-service",
						Namespace: "default",
						Instance:  "instance-1",
					},
					HostName: "test-host",
				},
			},
		},
		{
			name: "PID changing service (stale UID without existing attributes)",
			setup: func(r *SurveyMetricsReporter, m *mockEventMetrics) {
				// Setup: PID 1234 is already tracked with stale UID, but no service map entry
				staleUID := svc.UID{
					Name:      "old-service",
					Namespace: "default",
					Instance:  "instance-1",
				}
				r.pidTracker.AddPID(1234, staleUID)
				// Note: deliberately NOT adding to serviceMap to test this edge case
			},
			event: exec.ProcessEvent{
				Type: exec.ProcessEventCreated,
				File: &exec.FileInfo{
					Pid: 1234,
					Service: svc.Attrs{
						UID: svc.UID{
							Name:      "new-service",
							Namespace: "default",
							Instance:  "instance-1",
						},
						HostName: "test-host",
					},
				},
			},
			expectedCreate: nil,
			expectedDelete: []svc.UID{
				{
					Name:      "old-service",
					Namespace: "default",
					Instance:  "instance-1",
				},
			},
			expectedMap: map[svc.UID]svc.Attrs{
				{
					Name:      "new-service",
					Namespace: "default",
					Instance:  "instance-1",
				}: {
					UID: svc.UID{
						Name:      "new-service",
						Namespace: "default",
						Instance:  "instance-1",
					},
					HostName: "test-host",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockEventsStore := mockEventMetrics{}

			// Create a minimal metricsReporter with mocks
			reporter := &SurveyMetricsReporter{
				cfg:                &otelcfg.MetricsConfig{},
				log:                slog.Default(),
				serviceMap:         make(map[svc.UID][]attribute.KeyValue),
				pidTracker:         obiotel.NewPidServiceTracker(),
				createEventMetrics: mockEventsStore.createEventMetrics,
				deleteEventMetrics: mockEventsStore.deleteEventMetrics,
			}

			mockEventsStore.smr = reporter

			// Setup any initial state
			tt.setup(reporter, &mockEventsStore)

			// Execute the function under test
			reporter.onProcessEvent(context.Background(), &tt.event)

			// Verify create calls
			for i, cc := range tt.expectedCreate {
				c := reporter.attrsFromService(&cc)
				d := reporter.attrsFromService(mockEventsStore.createCalls[i])
				resourcesMatch(t, c, d)
			}

			// Verify delete calls
			idsMatch(t, tt.expectedDelete, mockEventsStore.deleteCalls)

			tm := map[svc.UID][]attribute.KeyValue{}

			for uid, attrs := range tt.expectedMap {
				tm[uid] = reporter.attrsFromService(&attrs)
			}

			// Verify service map state
			assert.Equal(t, tm, reporter.serviceMap,
				"Service map should match expected state")
		})
	}
}

func TestHandleProcessEventCreated_EdgeCases(t *testing.T) {
	t.Run("multiple PIDs for same service", func(t *testing.T) {
		mockEventsStore := newMockEventMetrics(nil)

		reporter := &SurveyMetricsReporter{
			cfg:                &otelcfg.MetricsConfig{},
			log:                slog.Default(),
			serviceMap:         make(map[svc.UID][]attribute.KeyValue),
			pidTracker:         obiotel.NewPidServiceTracker(),
			createEventMetrics: mockEventsStore.createEventMetrics,
			deleteEventMetrics: mockEventsStore.deleteEventMetrics,
		}
		mockEventsStore.smr = reporter

		uid := svc.UID{Name: "multi-pid-service", Namespace: "default", Instance: "instance-1"}
		service := svc.Attrs{UID: uid, HostName: "test-host"}

		// Add first PID
		event1 := exec.ProcessEvent{
			Type: exec.ProcessEventCreated,
			File: &exec.FileInfo{Pid: 1111, Service: service},
		}
		reporter.onProcessEvent(context.Background(), &event1)

		// Add second PID for same service
		event2 := exec.ProcessEvent{
			Type: exec.ProcessEventCreated,
			File: &exec.FileInfo{Pid: 2222, Service: service},
		}
		reporter.onProcessEvent(context.Background(), &event2)

		// Service should only be created once initially, then updated once for the same UID
		assert.Len(t, mockEventsStore.createCalls, 2) // One for each PID event
		assert.Len(t, mockEventsStore.deleteCalls, 1) // One delete when second event updates existing service
	})

	t.Run("concurrent service updates", func(t *testing.T) {
		mockEventsStore := newMockEventMetrics(nil)

		reporter := &SurveyMetricsReporter{
			cfg:                &otelcfg.MetricsConfig{},
			log:                slog.Default(),
			serviceMap:         make(map[svc.UID][]attribute.KeyValue),
			pidTracker:         obiotel.NewPidServiceTracker(),
			createEventMetrics: mockEventsStore.createEventMetrics,
			deleteEventMetrics: mockEventsStore.deleteEventMetrics,
		}
		mockEventsStore.smr = reporter

		uid := svc.UID{Name: "concurrent-service", Namespace: "default", Instance: "instance-1"}

		// Simulate rapid updates to same service with different metadata
		for i := 0; i < 5; i++ {
			service := svc.Attrs{
				UID:      uid,
				HostName: fmt.Sprintf("host-%d", i),
			}

			event := exec.ProcessEvent{
				Type: exec.ProcessEventCreated,
				File: &exec.FileInfo{Pid: int32(1000 + i), Service: service},
			}
			reporter.onProcessEvent(context.Background(), &event)
		}

		hostKey := attribute.Key(attr.HostName)
		// Should end up with latest service attributes
		finalService := reporter.serviceMap[uid]
		found := false
		for i := 0; i < len(finalService); i++ {
			if finalService[i].Key == hostKey {
				hostName := finalService[i].Value.AsString()
				assert.Equal(t, "host-4", hostName)
				found = true
				break
			}
		}

		assert.True(t, found)
		// Should have created 5 times and deleted 4 times (each update after first deletes previous)
		assert.Len(t, mockEventsStore.createCalls, 5)
		assert.Len(t, mockEventsStore.deleteCalls, 4)
	})
}

func resourcesMatch(t *testing.T, one []attribute.KeyValue, two []attribute.KeyValue) {
	assert.Equal(t, len(one), len(two))

	for i := 0; i < len(one); i++ {
		a := one[i]
		b := two[i]

		assert.Equal(t, a.Key, b.Key)
		assert.Equal(t, a.Value.AsString(), b.Value.AsString())
	}
}

func idsMatch(t *testing.T, one []svc.UID, two []svc.UID) {
	assert.Equal(t, len(one), len(two))

	for i := 0; i < len(one); i++ {
		a := one[i]
		b := two[i]

		assert.Equal(t, a.NameNamespace(), b.NameNamespace())
	}
}
