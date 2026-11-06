package main

import (
	"fmt"
	"os"

	tpencode "github.com/grafana/beyla/v3/poc/traceparent-encode"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "encode" {
		ns, name := "", "nginx"
		if len(os.Args) > 2 {
			name = os.Args[2]
		}
		if len(os.Args) > 3 {
			ns, name = os.Args[2], os.Args[3]
		}
		id := tpencode.Identity{Namespace: ns, Name: name}
		if err := tpencode.DumpExample(os.Stdout, id, id); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := tpencode.Report(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
