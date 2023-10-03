package services

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type yamlFile struct {
	Services DefinitionCriteria `yaml:"services"`
}

func TestYAMLParse_PathRegexp(t *testing.T) {
	inputFile := `
services:
  - name: foo
    exe_path_regexp: "^abc$"
`
	yf := yamlFile{}
	require.NoError(t, yaml.Unmarshal([]byte(inputFile), &yf))

	require.Len(t, yf.Services, 1)

	assert.True(t, yf.Services[0].Path.IsSet())
	assert.True(t, yf.Services[0].Path.MatchString("abc"))
	assert.False(t, yf.Services[0].Path.MatchString("cabc"))
	assert.False(t, yf.Services[0].Path.MatchString("abca"))

	assert.Zero(t, yf.Services[0].OpenPorts.Len())
}

func TestYAMLParse_PathRegexp_Errors(t *testing.T) {
	t.Run("wrong regular expression", func(t *testing.T) {
		require.Error(t, yaml.Unmarshal([]byte(`services:
  - exe_path_regexp: "$a\("`), &yamlFile{}))
	})
	t.Run("wrong regular pathregexp type", func(t *testing.T) {
		require.Error(t, yaml.Unmarshal([]byte(`services:
  - exe_path_regexp:
      other: kind`), &yamlFile{}))
	})
}

func TestYAMLParse_PortEnum(t *testing.T) {
	var portEnumYAML = func(enum string) PortEnum {
		yf := yamlFile{}
		err := yaml.Unmarshal([]byte(fmt.Sprintf("services:\n  - open_ports: %s\n", enum)), &yf)
		require.NoError(t, err)
		require.Len(t, yf.Services, 1)
		assert.False(t, yf.Services[0].Path.IsSet())
		return yf.Services[0].OpenPorts
	}
	t.Run("single port number", func(t *testing.T) {
		pe := portEnumYAML("80")
		require.True(t, pe.Matches(80))
		require.False(t, pe.Matches(8))
		require.False(t, pe.Matches(79))
		require.False(t, pe.Matches(81))
		require.False(t, pe.Matches(8080))
	})
	t.Run("comma-separated port numbers", func(t *testing.T) {
		pe := portEnumYAML("80,8080")
		require.True(t, pe.Matches(80))
		require.True(t, pe.Matches(8080))
		require.False(t, pe.Matches(79))
		require.False(t, pe.Matches(8081))
	})
	t.Run("ranges", func(t *testing.T) {
		pe := portEnumYAML("8000-8999")
		require.True(t, pe.Matches(8000))
		require.True(t, pe.Matches(8999))
		require.True(t, pe.Matches(8080))
		require.False(t, pe.Matches(7999))
		require.False(t, pe.Matches(9000))
	})
	t.Run("merging ranges and single ports, and lots of spaces", func(t *testing.T) {
		pe := portEnumYAML("   80\t,   100 -200,443, 8000- 8999   ")
		require.True(t, pe.Matches(80))
		require.True(t, pe.Matches(100))
		require.True(t, pe.Matches(200))
		require.True(t, pe.Matches(443))
		require.True(t, pe.Matches(8000))
		require.True(t, pe.Matches(8999))
		require.True(t, pe.Matches(8080))
		require.False(t, pe.Matches(1))
		require.False(t, pe.Matches(90))
		require.False(t, pe.Matches(300))
		require.False(t, pe.Matches(1000))
		require.False(t, pe.Matches(15000))
	})
}

func TestYAMLParse_PortEnum_Errors(t *testing.T) {
	var assertError = func(desc, enum string) {
		t.Run(desc, func(t *testing.T) {
			err := yaml.Unmarshal([]byte(fmt.Sprintf("services:\n  - open_ports: %s\n", enum)), &yamlFile{})
			assert.Error(t, err)
		})
	}
	assertError("only comma", ",")
	assertError("only dash", "-")
	assertError("not a number", "1a")
	assertError("starting with comma", ",33")
	assertError("ending with comma", "33,")
	assertError("unfinished range", "32,15-")
	assertError("unstarted range", "12,-13")
	assertError("wrong symbols", "1,2,*3,4")
}
