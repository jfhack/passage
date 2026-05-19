package quickdocker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSpecProjectName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spec.yaml")
	if err := os.WriteFile(path, []byte(`
server:
  listen: 0.0.0.0:4790
  address: example.com:4790
  mode: host
client:
  identity:
    id: demo
  mode: host
project_name: demo
services:
  web:
    client: 127.0.0.1:8888
    server: 0.0.0.0:8080
`), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := Load(path)
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	if spec.ProjectName != "demo" {
		t.Fatalf("project name = %q, want demo", spec.ProjectName)
	}
}

func TestRenderComposeProjectNames(t *testing.T) {
	spec := &Spec{
		ProjectName: "demo",
		Server: ServerSection{
			Listen:  "0.0.0.0:4790",
			Address: "example.com:4790",
			Mode:    "isolated",
		},
		Client: ClientSection{
			Identity: ClientIdentity{ID: "demo"},
			Mode:     "isolated",
		},
		Services: map[string]ServiceEntry{
			"web": {Client: "127.0.0.1:8888", Server: "0.0.0.0:8080"},
		},
	}
	if err := spec.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	serverCompose := renderServerCompose(spec)
	clientCompose := renderClientCompose(spec)
	for _, tc := range []struct {
		name string
		got  string
		want string
	}{
		{"server project", serverCompose, "name: demo-passage-server"},
		{"server container", serverCompose, "container_name: demo-passage-server"},
		{"client project", clientCompose, "name: demo-passage-client"},
		{"client container", clientCompose, "container_name: demo-passage-client"},
	} {
		if !strings.Contains(tc.got, tc.want) {
			t.Fatalf("%s missing %q in:\n%s", tc.name, tc.want, tc.got)
		}
	}
}
