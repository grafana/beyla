package prom

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export/otel"
)

type mockEventMetrics struct {
	createCalls []svc.Attrs
	deleteCalls []svc.Attrs
}

func newMockEventMetrics() *mockEventMetrics {
	return &mockEventMetrics{
		createCalls: make([]svc.Attrs, 0),
		deleteCalls: make([]svc.Attrs, 0),
	}
}

func (m *mockEventMetrics) createEventMetrics(service *svc.Attrs) {
	m.createCalls = append(m.createCalls, *service)
}

func (m *mockEventMetrics) deleteEventMetrics(uid svc.UID, service *svc.Attrs) {
	m.deleteCalls = append(m.deleteCalls, *service)
}

func TestHandleProcessEventCreated(t *testing.T) {
	tests := []struct {
		name           string
		setup          func(*surveyMetricsReporter, *mockEventMetrics)
		event          exec.ProcessEvent
		expectedCreate []svc.Attrs
		expectedDelete []svc.Attrs
		expectedMap    map[svc.UID]svc.Attrs
	}{
		{
			name: "new service - fresh start",
			setup: func(*surveyMetricsReporter, *mockEventMetrics) {
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
			setup: func(r *surveyMetricsReporter, _ *mockEventMetrics) {
				// Pre-populate service map with existing service
				uid := svc.UID{
					Name:      "test-service",
					Namespace: "default",
					Instance:  "instance-1",
				}
				r.serviceMap[uid] = svc.Attrs{
					UID:      uid,
					HostName: "old-host",
				}
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
			expectedDelete: []svc.Attrs{
				{
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "default",
						Instance:  "instance-1",
					},
					HostName: "old-host",
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
			setup: func(r *surveyMetricsReporter, _ *mockEventMetrics) {
				// Setup: PID 1234 is already tracked with stale UID
				staleUID := svc.UID{
					Name:      "old-service",
					Namespace: "default",
					Instance:  "instance-1",
				}
				r.pidsTracker.AddPID(1234, staleUID)

				// Add stale service to service map
				r.serviceMap[staleUID] = svc.Attrs{
					UID:      staleUID,
					HostName: "test-host",
				}
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
			expectedDelete: []svc.Attrs{
				{
					UID: svc.UID{
						Name:      "old-service",
						Namespace: "default",
						Instance:  "instance-1",
					},
					HostName: "test-host",
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
			setup: func(r *surveyMetricsReporter, _ *mockEventMetrics) {
				// Setup: PID 1234 is already tracked with stale UID, but no service map entry
				staleUID := svc.UID{
					Name:      "old-service",
					Namespace: "default",
					Instance:  "instance-1",
				}
				r.pidsTracker.AddPID(1234, staleUID)
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
			expectedDelete: nil,
			expectedMap:    map[svc.UID]svc.Attrs{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockEventsStore := mockEventMetrics{}

			// Create a minimal metricsReporter with mocks
			reporter := &surveyMetricsReporter{
				serviceMap:         make(map[svc.UID]svc.Attrs),
				pidsTracker:        otel.NewPidServiceTracker(),
				createEventMetrics: mockEventsStore.createEventMetrics,
				deleteEventMetrics: mockEventsStore.deleteEventMetrics,
			}

			// Setup any initial state
			tt.setup(reporter, &mockEventsStore)

			// Create a test logger (using slog.Default for simplicity)
			logger := slog.Default()

			// Execute the function under test
			reporter.handleProcessEvent(tt.event, logger)

			// Verify create calls
			assert.Equal(t, tt.expectedCreate, mockEventsStore.createCalls,
				"Create event metrics calls should match expected")

			// Verify delete calls
			assert.Equal(t, tt.expectedDelete, mockEventsStore.deleteCalls,
				"Delete event metrics calls should match expected")

			// Verify service map state
			assert.Equal(t, tt.expectedMap, reporter.serviceMap,
				"Service map should match expected state")
		})
	}
}

func TestHandleProcessEventCreated_EdgeCases(t *testing.T) {
	t.Run("multiple PIDs for same service", func(t *testing.T) {
		mockEventsStore := newMockEventMetrics()

		reporter := &surveyMetricsReporter{
			serviceMap:         make(map[svc.UID]svc.Attrs),
			pidsTracker:        otel.NewPidServiceTracker(),
			createEventMetrics: mockEventsStore.createEventMetrics,
			deleteEventMetrics: mockEventsStore.deleteEventMetrics,
		}

		uid := svc.UID{Name: "multi-pid-service", Namespace: "default", Instance: "instance-1"}
		service := svc.Attrs{UID: uid, HostName: "test-host"}

		// Add first PID
		event1 := exec.ProcessEvent{
			Type: exec.ProcessEventCreated,
			File: &exec.FileInfo{Pid: 1111, Service: service},
		}
		reporter.handleProcessEvent(event1, slog.Default())

		// Add second PID for same service
		event2 := exec.ProcessEvent{
			Type: exec.ProcessEventCreated,
			File: &exec.FileInfo{Pid: 2222, Service: service},
		}
		reporter.handleProcessEvent(event2, slog.Default())

		// Service should only be created once initially, then updated once for the same UID
		assert.Len(t, mockEventsStore.createCalls, 2) // One for each PID event
		assert.Len(t, mockEventsStore.deleteCalls, 1) // One delete when second event updates existing service
	})

	t.Run("concurrent service updates", func(t *testing.T) {
		mockEventsStore := newMockEventMetrics()

		reporter := &surveyMetricsReporter{
			serviceMap:         make(map[svc.UID]svc.Attrs),
			pidsTracker:        otel.NewPidServiceTracker(),
			createEventMetrics: mockEventsStore.createEventMetrics,
			deleteEventMetrics: mockEventsStore.deleteEventMetrics,
		}

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
			reporter.handleProcessEvent(event, slog.Default())
		}

		// Should end up with latest service attributes
		finalService := reporter.serviceMap[uid]
		assert.Equal(t, "host-4", finalService.HostName)

		// Should have created 5 times and deleted 4 times (each update after first deletes previous)
		assert.Len(t, mockEventsStore.createCalls, 5)
		assert.Len(t, mockEventsStore.deleteCalls, 4)
	})
}
