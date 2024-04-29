package pipe

type creationOptions struct {
	// if 0, channel is unbuffered
	channelBufferLen int
}

var defaultOptions = creationOptions{
	channelBufferLen: 0,
}

// Option allows overriding the default properties of the nodes and connections of a pipeline.
type Option func(options *creationOptions)

// ChannelBufferLen is an Option that allows specifying the length of the input
// channels for a given node. The default value is 0, which means that the channels
// are unbuffered.
func ChannelBufferLen(length int) Option {
	return func(options *creationOptions) {
		options.channelBufferLen = length
	}
}
