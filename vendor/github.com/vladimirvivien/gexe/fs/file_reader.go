package fs

import (
	"bufio"
	"bytes"
	"io"
	"os"

	"github.com/vladimirvivien/gexe/vars"
)

type FileReader struct {
	err  error
	path string
	info os.FileInfo
	mode os.FileMode
	vars *vars.Variables
}

// Read creates a new FileReader using the provided path.
// A non-nil FileReader.Err() is returned if file does not exist
// or another error is generated.
func Read(path string) *FileReader {
	info, err := os.Stat(path)
	if err != nil {
		return &FileReader{err: err, path: path}
	}
	return &FileReader{path: path, info: info, mode: info.Mode()}
}

// ReadWithVars creates a new FileReader and sets the reader's session variables
func ReadWithVars(path string, variables *vars.Variables) *FileReader {
	reader := Read(variables.Eval(path))
	reader.vars = variables
	return reader
}

// SetVars sets the FileReader's session variables
func (fr *FileReader) SetVars(variables *vars.Variables) *FileReader {
	fr.vars = variables
	return fr
}

// Err returns an operation error during file read.
func (fr *FileReader) Err() error {
	return fr.err
}

// Info surfaces the os.FileInfo for the associated file
func (fr *FileReader) Info() os.FileInfo {
	return fr.info
}

// String returns the content of the file as a string value
func (fr *FileReader) String() string {
	file, err := os.Open(fr.path)
	if err != nil {
		fr.err = err
		return ""
	}
	defer file.Close()

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(file); err != nil {
		fr.err = err
		return ""
	}

	return buf.String()
}

// Lines returns the content of the file as slice of string
func (fr *FileReader) Lines() []string {
	file, err := os.Open(fr.path)
	if err != nil {
		fr.err = err
		return []string{}
	}
	var lines []string
	scnr := bufio.NewScanner(file)

	for scnr.Scan() {
		lines = append(lines, scnr.Text())
	}

	if scnr.Err() != nil {
		fr.err = scnr.Err()
		return []string{}
	}

	return lines
}

// Bytes returns the content of the file as []byte
func (fr *FileReader) Bytes() []byte {
	file, err := os.Open(fr.path)
	if err != nil {
		fr.err = err
		return []byte{}
	}
	defer file.Close()

	buf := new(bytes.Buffer)

	if _, err := buf.ReadFrom(file); err != nil {
		fr.err = err
		return []byte{}
	}

	return buf.Bytes()
}

// Into reads the content of the file and writes
// it into the specified Writer
func (fr *FileReader) Into(w io.Writer) *FileReader {
	file, err := os.Open(fr.path)
	if err != nil {
		fr.err = err
		return fr
	}
	defer file.Close()
	if _, err := io.Copy(w, file); err != nil {
		fr.err = err
	}
	return fr
}
