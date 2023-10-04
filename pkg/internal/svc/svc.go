package svc

// ID stores the coordinates that uniquely identifies a service:
// its name and optionally a namespace
type ID struct {
	Name      string
	Namespace string
}

func (i *ID) String() string {
	if i.Namespace != "" {
		return i.Namespace + "/" + i.Name
	}
	return i.Name
}
