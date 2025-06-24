package nodejs

func withNetNS(_ int, fn func() error) error {
	return fn()
}
