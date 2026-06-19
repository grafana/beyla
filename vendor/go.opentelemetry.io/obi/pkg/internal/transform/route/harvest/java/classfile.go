// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package java // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/java"

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const classFileMagic = 0xCAFEBABE

// JVM constant pool tags, as defined by the Java Virtual Machine
// Specification 4.4 (The Constant Pool).
const (
	cpTagUtf8               uint8 = 1
	cpTagInteger            uint8 = 3
	cpTagFloat              uint8 = 4
	cpTagLong               uint8 = 5
	cpTagDouble             uint8 = 6
	cpTagClass              uint8 = 7
	cpTagString             uint8 = 8
	cpTagFieldref           uint8 = 9
	cpTagMethodref          uint8 = 10
	cpTagInterfaceMethodref uint8 = 11
	cpTagNameAndType        uint8 = 12
	cpTagMethodHandle       uint8 = 15
	cpTagMethodType         uint8 = 16
	cpTagDynamic            uint8 = 17
	cpTagInvokeDynamic      uint8 = 18
	cpTagModule             uint8 = 19
	cpTagPackage            uint8 = 20
)

type classFile struct {
	classAnnotations  []annotation
	methodAnnotations [][]annotation
}

type annotation struct {
	descriptor string
	elements   map[string][]string
	nested     []annotation
}

type constantPoolEntry struct {
	tag   uint8
	utf8  string
	index uint16
}

type constantPool []constantPoolEntry

type classReader struct {
	data []byte
	off  int
}

type elementValue struct {
	strings     []string
	annotations []annotation
}

func parseClassFile(data []byte) (*classFile, error) {
	reader := classReader{data: data}

	magic, err := reader.u4()
	if err != nil {
		return nil, err
	}
	if magic != classFileMagic {
		return nil, fmt.Errorf("invalid class file magic: 0x%x", magic)
	}

	if err := reader.skip(4); err != nil {
		return nil, err
	}

	cp, err := parseConstantPool(&reader)
	if err != nil {
		return nil, err
	}

	if err := reader.skip(6); err != nil {
		return nil, err
	}

	interfacesCount, err := reader.u2()
	if err != nil {
		return nil, err
	}
	if err := reader.skip(int(interfacesCount) * 2); err != nil {
		return nil, err
	}

	fieldsCount, err := reader.u2()
	if err != nil {
		return nil, err
	}
	for range int(fieldsCount) {
		if err := skipMember(&reader); err != nil {
			return nil, err
		}
	}

	methodsCount, err := reader.u2()
	if err != nil {
		return nil, err
	}
	class := &classFile{}
	for range int(methodsCount) {
		annotations, err := parseMemberAnnotations(&reader, cp)
		if err != nil {
			return nil, err
		}
		if len(annotations) > 0 {
			class.methodAnnotations = append(class.methodAnnotations, annotations)
		}
	}

	classAnnotations, err := parseAttributesAnnotations(&reader, cp)
	if err != nil {
		return nil, err
	}
	class.classAnnotations = classAnnotations

	return class, nil
}

func parseConstantPool(reader *classReader) (constantPool, error) {
	count, err := reader.u2()
	if err != nil {
		return nil, err
	}

	cp := make(constantPool, count)
	for i := uint16(1); i < count; i++ {
		tag, err := reader.u1()
		if err != nil {
			return nil, err
		}
		cp[i].tag = tag

		switch tag {
		case cpTagUtf8:
			length, err := reader.u2()
			if err != nil {
				return nil, err
			}
			b, err := reader.bytes(int(length))
			if err != nil {
				return nil, err
			}
			cp[i].utf8 = string(b)
		case cpTagInteger, cpTagFloat:
			if err := reader.skip(4); err != nil {
				return nil, err
			}
		case cpTagLong, cpTagDouble:
			if err := reader.skip(8); err != nil {
				return nil, err
			}
			// Long and Double constants occupy two entries in the
			// constant pool table; skip the unusable next index.
			i++
		case cpTagClass, cpTagString, cpTagMethodType, cpTagModule, cpTagPackage:
			index, err := reader.u2()
			if err != nil {
				return nil, err
			}
			cp[i].index = index
		case cpTagFieldref, cpTagMethodref, cpTagInterfaceMethodref, cpTagNameAndType, cpTagDynamic, cpTagInvokeDynamic:
			if err := reader.skip(4); err != nil {
				return nil, err
			}
		case cpTagMethodHandle:
			if err := reader.skip(3); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported constant pool tag %d", tag)
		}
	}

	return cp, nil
}

func skipMember(reader *classReader) error {
	if err := reader.skip(6); err != nil {
		return err
	}
	return skipAttributes(reader)
}

func parseMemberAnnotations(reader *classReader, cp constantPool) ([]annotation, error) {
	if err := reader.skip(6); err != nil {
		return nil, err
	}
	return parseAttributesAnnotations(reader, cp)
}

func skipAttributes(reader *classReader) error {
	count, err := reader.u2()
	if err != nil {
		return err
	}
	for range int(count) {
		if err := reader.skip(2); err != nil {
			return err
		}
		length, err := reader.u4()
		if err != nil {
			return err
		}
		if err := reader.skip(int(length)); err != nil {
			return err
		}
	}
	return nil
}

func parseAttributesAnnotations(reader *classReader, cp constantPool) ([]annotation, error) {
	count, err := reader.u2()
	if err != nil {
		return nil, err
	}

	var annotations []annotation
	for range int(count) {
		nameIndex, err := reader.u2()
		if err != nil {
			return nil, err
		}
		length, err := reader.u4()
		if err != nil {
			return nil, err
		}
		data, err := reader.bytes(int(length))
		if err != nil {
			return nil, err
		}

		name, ok := cp.utf8(nameIndex)
		if !ok || !isAnnotationsAttribute(name) {
			continue
		}

		attrAnnotations, err := parseAnnotationsAttribute(data, cp)
		if err != nil {
			return nil, err
		}
		annotations = append(annotations, attrAnnotations...)
	}

	return annotations, nil
}

func isAnnotationsAttribute(name string) bool {
	return name == "RuntimeVisibleAnnotations" || name == "RuntimeInvisibleAnnotations"
}

func parseAnnotationsAttribute(data []byte, cp constantPool) ([]annotation, error) {
	reader := classReader{data: data}
	count, err := reader.u2()
	if err != nil {
		return nil, err
	}

	annotations := make([]annotation, 0, count)
	for range int(count) {
		ann, err := parseAnnotation(&reader, cp)
		if err != nil {
			return nil, err
		}
		annotations = append(annotations, ann)
	}
	return annotations, nil
}

func parseAnnotation(reader *classReader, cp constantPool) (annotation, error) {
	typeIndex, err := reader.u2()
	if err != nil {
		return annotation{}, err
	}
	descriptor, ok := cp.utf8(typeIndex)
	if !ok {
		return annotation{}, fmt.Errorf("invalid annotation type index %d", typeIndex)
	}

	pairCount, err := reader.u2()
	if err != nil {
		return annotation{}, err
	}

	ann := annotation{
		descriptor: descriptor,
		elements:   map[string][]string{},
	}
	for range int(pairCount) {
		nameIndex, err := reader.u2()
		if err != nil {
			return annotation{}, err
		}
		name, ok := cp.utf8(nameIndex)
		if !ok {
			return annotation{}, fmt.Errorf("invalid annotation element name index %d", nameIndex)
		}

		values, err := parseElementValue(reader, cp)
		if err != nil {
			return annotation{}, err
		}
		if len(values.strings) > 0 {
			ann.elements[name] = append(ann.elements[name], values.strings...)
		}
		if len(values.annotations) > 0 {
			ann.nested = append(ann.nested, values.annotations...)
		}
	}

	return ann, nil
}

func parseElementValue(reader *classReader, cp constantPool) (elementValue, error) {
	tag, err := reader.u1()
	if err != nil {
		return elementValue{}, err
	}

	switch tag {
	case 's':
		index, err := reader.u2()
		if err != nil {
			return elementValue{}, err
		}
		value, ok := cp.stringValue(index)
		if !ok {
			return elementValue{}, fmt.Errorf("invalid string annotation value index %d", index)
		}
		return elementValue{strings: []string{value}}, nil
	case '[':
		count, err := reader.u2()
		if err != nil {
			return elementValue{}, err
		}
		var values elementValue
		for range int(count) {
			nested, err := parseElementValue(reader, cp)
			if err != nil {
				return elementValue{}, err
			}
			values.strings = append(values.strings, nested.strings...)
			values.annotations = append(values.annotations, nested.annotations...)
		}
		return values, nil
	case 'e':
		return elementValue{}, reader.skip(4)
	case 'c':
		return elementValue{}, reader.skip(2)
	case '@':
		ann, err := parseAnnotation(reader, cp)
		if err != nil {
			return elementValue{}, err
		}
		return elementValue{annotations: []annotation{ann}}, nil
	case 'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z':
		return elementValue{}, reader.skip(2)
	default:
		return elementValue{}, fmt.Errorf("unsupported annotation value tag %q", tag)
	}
}

func (cp constantPool) utf8(index uint16) (string, bool) {
	if int(index) >= len(cp) || cp[index].tag != 1 {
		return "", false
	}
	return cp[index].utf8, true
}

func (cp constantPool) stringValue(index uint16) (string, bool) {
	if value, ok := cp.utf8(index); ok {
		return value, true
	}
	if int(index) >= len(cp) || cp[index].tag != 8 {
		return "", false
	}
	return cp.utf8(cp[index].index)
}

func (r *classReader) u1() (uint8, error) {
	if r.off+1 > len(r.data) {
		return 0, errors.New("unexpected end of class file")
	}
	value := r.data[r.off]
	r.off++
	return value, nil
}

func (r *classReader) u2() (uint16, error) {
	if r.off+2 > len(r.data) {
		return 0, errors.New("unexpected end of class file")
	}
	value := binary.BigEndian.Uint16(r.data[r.off:])
	r.off += 2
	return value, nil
}

func (r *classReader) u4() (uint32, error) {
	if r.off+4 > len(r.data) {
		return 0, errors.New("unexpected end of class file")
	}
	value := binary.BigEndian.Uint32(r.data[r.off:])
	r.off += 4
	return value, nil
}

func (r *classReader) bytes(n int) ([]byte, error) {
	if n < 0 || r.off+n > len(r.data) {
		return nil, errors.New("unexpected end of class file")
	}
	value := r.data[r.off : r.off+n]
	r.off += n
	return value, nil
}

func (r *classReader) skip(n int) error {
	_, err := r.bytes(n)
	return err
}
