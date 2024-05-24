package process

import "github.com/shirou/gopsutil/process"

type Sample struct {
	ProcessDisplayName    string   `json:"processDisplayName"`
	ProcessID             int32    `json:"processId"`
	CommandName           string   `json:"commandName"`
	User                  string   `json:"userName,omitempty"`
	MemoryRSSBytes        int64    `json:"memoryResidentSizeBytes"`
	MemoryVMSBytes        int64    `json:"memoryVirtualSizeBytes"`
	CPUPercent            float64  `json:"cpuPercent"`
	CPUUserPercent        float64  `json:"cpuUserPercent"`
	CPUSystemPercent      float64  `json:"cpuSystemPercent"`
	ContainerImage        string   `json:"containerImage,omitempty"`
	ContainerImageName    string   `json:"containerImageName,omitempty"`
	ContainerName         string   `json:"containerName,omitempty"`
	ContainerID           string   `json:"containerId,omitempty"`
	Contained             string   `json:"contained,omitempty"`
	CmdLine               string   `json:"commandLine,omitempty"`
	Status                string   `json:"state,omitempty"`
	ParentProcessID       int32    `json:"parentProcessId,omitempty"`
	ThreadCount           int32    `json:"threadCount,omitempty"`
	FdCount               *int32   `json:"fileDescriptorCount,omitempty"`
	IOReadCountPerSecond  *float64 `json:"ioReadCountPerSecond,omitempty"`
	IOWriteCountPerSecond *float64 `json:"ioWriteCountPerSecond,omitempty"`
	IOReadBytesPerSecond  *float64 `json:"ioReadBytesPerSecond,omitempty"`
	IOWriteBytesPerSecond *float64 `json:"ioWriteBytesPerSecond,omitempty"`
	IOTotalReadCount      *uint64  `json:"ioTotalReadCount,omitempty"`
	IOTotalWriteCount     *uint64  `json:"ioTotalWriteCount,omitempty"`
	IOTotalReadBytes      *uint64  `json:"ioTotalReadBytes,omitempty"`
	IOTotalWriteBytes     *uint64  `json:"ioTotalWriteBytes,omitempty"`
	// Auxiliary values, not to be reported
	LastIOCounters  *process.IOCountersStat `json:"-"`
	ContainerLabels map[string]string       `json:"-"`
}
