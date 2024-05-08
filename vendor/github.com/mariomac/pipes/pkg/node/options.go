package node

type creationOptions struct {
	// if 0, channel is unbuffered
	channelBufferLen int
}

var defaultOptions = creationOptions{
	channelBufferLen: 0,
}

// Option allows overriding the default values of node instantiation
// Deprecated package. Use github.com/mariomac/pipes/pipe package
type Option func(options *creationOptions)

// ChannelBufferLen is a node.Option that allows specifying the length of the input
// channels for a given node. The default value is 0, which means that the channels
// are unbuffered.
// Deprecated package. Use github.com/mariomac/pipes/pipe package
func ChannelBufferLen(length int) Option {
	return func(options *creationOptions) {
		options.channelBufferLen = length
	}
}
