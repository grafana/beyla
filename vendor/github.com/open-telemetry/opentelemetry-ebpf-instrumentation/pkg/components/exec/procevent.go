package exec

type ProcessEventType int

const (
	ProcessEventCreated = ProcessEventType(iota)
	ProcessEventTerminated
)

type ProcessEvent struct {
	File *FileInfo
	Type ProcessEventType
}
