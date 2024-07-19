package kubeflags

type EnableFlag string

const (
	EnabledTrue       = EnableFlag("true")
	EnabledFalse      = EnableFlag("false")
	EnabledAutodetect = EnableFlag("autodetect")
	EnabledDefault    = EnabledFalse
)
