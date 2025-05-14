package exec

type ProcessEventType int

const (
	ProcessEventCreated = ProcessEventType(iota)
	ProcessEventTerminated
	ProcessEventSurveyCreated
)

type ProcessEvent struct {
	File *FileInfo
	Type ProcessEventType
}
