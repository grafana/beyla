package fs

import (
	"io"
	"os"

	"github.com/vladimirvivien/gexe/vars"
)

type FileWriter struct {
	path  string
	err   error
	finfo os.FileInfo
	mode  os.FileMode
	flags int
	vars  *vars.Variables
}

// Write creates a new FileWriter with flags os.O_CREATE | os.O_TRUNC | os.O_WRONLY  and mode 0644.
func Write(path string) *FileWriter {
	fw := &FileWriter{path: path, flags: os.O_CREATE | os.O_TRUNC | os.O_WRONLY, mode: 0644, vars: &vars.Variables{}}
	info, err := os.Stat(fw.path)
	if err == nil {
		fw.finfo = info
	}
	return fw
}

// WriteWithVars creates a new FileWriter and sets sessions variables
func WriteWithVars(path string, variables *vars.Variables) *FileWriter {
	fw := Write(variables.Eval(path))
	fw.vars = variables
	return fw
}

// Append creates a new FileWriter with flags os.O_CREATE | os.O_APPEND | os.O_WRONLY and mode 0644
func Append(path string) *FileWriter {
	fw := &FileWriter{path: path, flags: os.O_CREATE | os.O_APPEND | os.O_WRONLY, mode: 0644}
	info, err := os.Stat(fw.path)
	if err == nil {
		fw.finfo = info
	}

	return fw
}

// AppendWithVars creates a new FileWriter and sets session variables
func AppendWitVars(path string, variables *vars.Variables) *FileWriter {
	fw := Append(variables.Eval(path))
	fw.vars = variables
	return fw
}

// SetVars sets session variables for FileWriter
func (fw *FileWriter) SetVars(variables *vars.Variables) *FileWriter {
	if variables != nil {
		fw.vars = variables
	}
	return fw
}

func (fw *FileWriter) WithMode(mode os.FileMode) *FileWriter {
	fw.mode = mode
	return fw
}

// Err returns FileWriter error during execution
func (fw *FileWriter) Err() error {
	return fw.err
}

// Info returns the os.FileInfo for the associated file
func (fw *FileWriter) Info() os.FileInfo {
	return fw.finfo
}

// String writes the provided str into the file. Any
// error that occurs can be accessed with FileWriter.Err().
func (fw *FileWriter) String(str string) *FileWriter {
	file, err := os.OpenFile(fw.path, fw.flags, fw.mode)
	if err != nil {
		fw.err = err
		return fw
	}
	defer file.Close()
	if fw.finfo, fw.err = file.Stat(); fw.err != nil {
		return fw
	}

	if _, err := file.WriteString(str); err != nil {
		fw.err = err
	}
	return fw
}

// Lines writes the slice of strings into the file.
// Any error will be captured and returned via FileWriter.Err().
func (fw *FileWriter) Lines(lines []string) *FileWriter {
	file, err := os.OpenFile(fw.path, fw.flags, fw.mode)
	if err != nil {
		fw.err = err
		return fw
	}
	defer file.Close()
	if fw.finfo, fw.err = file.Stat(); fw.err != nil {
		return fw
	}

	len := len(lines)
	for i, line := range lines {
		if _, err := file.WriteString(line); err != nil {
			fw.err = err
			return fw
		}
		if len > (i + 1) {
			if _, err := file.Write([]byte{'\n'}); err != nil {
				fw.err = err
				return fw
			}
		}
	}
	return fw
}

// Bytes writes the []bytre provided into the file.
// Any error can be accessed using FileWriter.Err().
func (fw *FileWriter) Bytes(data []byte) *FileWriter {
	file, err := os.OpenFile(fw.path, fw.flags, fw.mode)
	if err != nil {
		fw.err = err
		return fw
	}
	defer file.Close()
	if fw.finfo, fw.err = file.Stat(); fw.err != nil {
		return fw
	}

	if _, err := file.Write(data); err != nil {
		fw.err = err
	}
	return fw
}

// From streams bytes from the provided io.Reader r and
// writes them to the file. Any error will be captured
// and returned by fw.Err().
func (fw *FileWriter) From(r io.Reader) *FileWriter {
	file, err := os.OpenFile(fw.path, fw.flags, fw.mode)
	if err != nil {
		fw.err = err
		return fw
	}
	defer file.Close()
	if fw.finfo, fw.err = file.Stat(); fw.err != nil {
		return fw
	}

	if _, err := io.Copy(file, r); err != nil {
		fw.err = err
	}
	return fw
}
