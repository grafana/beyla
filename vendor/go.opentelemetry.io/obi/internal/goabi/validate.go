// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goabi // import "go.opentelemetry.io/obi/internal/goabi"

import (
	"encoding/binary"
	"errors"
)

func validateTypeMetadata(metadata *TypeMetadata) error {
	if metadata.TFlagSize != uint64(binary.Size(uint8(0))) ||
		metadata.KindSize != uint64(binary.Size(uint8(0))) ||
		metadata.NameOffsetSize != uint64(binary.Size(int32(0))) {
		return errors.New("unsupported Go runtime ABI scalar sizes")
	}

	pointerSize := uint64(binary.Size(uint64(0)))
	if !fieldFits(metadata.TypeTFlagOffset, metadata.TFlagSize, metadata.TypeSize) ||
		!fieldFits(metadata.TypeKindOffset, metadata.KindSize, metadata.TypeSize) ||
		!fieldFits(metadata.TypeNameOffset, metadata.NameOffsetSize, metadata.TypeSize) ||
		metadata.SliceLenOffset != pointerSize ||
		!fieldFits(metadata.InterfaceMethodsOffset, metadata.SliceLenOffset+pointerSize, metadata.InterfaceUncommonOffset) ||
		!fieldFits(metadata.ITabInterOffset, pointerSize, metadata.ITabBaseSize) ||
		!fieldFits(metadata.ITabTypeOffset, pointerSize, metadata.ITabBaseSize) ||
		metadata.ITabFunOffset > metadata.ITabBaseSize-pointerSize ||
		metadata.ITabFunOffset+pointerSize != metadata.ITabBaseSize ||
		metadata.ITabInterOffset%pointerSize != 0 || metadata.ITabTypeOffset%pointerSize != 0 ||
		metadata.ITabFunOffset%pointerSize != 0 ||
		metadata.ITabInterOffset == metadata.ITabTypeOffset ||
		metadata.ITabInterOffset == metadata.ITabFunOffset ||
		metadata.ITabTypeOffset == metadata.ITabFunOffset ||
		!allAtLeast(metadata.TypeSize,
			metadata.ArrayUncommonOffset,
			metadata.ChanUncommonOffset,
			metadata.FuncUncommonOffset,
			metadata.InterfaceUncommonOffset,
			metadata.MapUncommonOffset,
			metadata.PointerUncommonOffset,
			metadata.SliceUncommonOffset,
			metadata.StructUncommonOffset,
		) {
		return errors.New("invalid Go runtime ABI layout")
	}

	maxByte := uint64(^uint8(0))
	if metadata.TFlagUncommonMask > maxByte || metadata.TFlagExtraStarMask > maxByte ||
		metadata.KindDirectIfaceFlag > maxByte || metadata.ArrayKind > maxByte ||
		metadata.ChanKind > maxByte || metadata.FuncKind > maxByte || metadata.InterfaceKind > maxByte ||
		metadata.MapKind > maxByte || metadata.PointerKind > maxByte || metadata.SliceKind > maxByte ||
		metadata.StructKind > maxByte {
		return errors.New("invalid Go runtime ABI facts")
	}
	if !powerOfTwo(metadata.TFlagUncommonMask) || !powerOfTwo(metadata.TFlagExtraStarMask) ||
		metadata.TFlagUncommonMask == metadata.TFlagExtraStarMask || !powerOfTwo(metadata.KindDirectIfaceFlag) {
		return errors.New("invalid Go runtime ABI constants")
	}
	kindMask := metadata.KindDirectIfaceFlag - 1
	if !distinctValuesWithin(kindMask,
		metadata.ArrayKind,
		metadata.ChanKind,
		metadata.FuncKind,
		metadata.InterfaceKind,
		metadata.MapKind,
		metadata.PointerKind,
		metadata.SliceKind,
		metadata.StructKind,
	) {
		return errors.New("invalid Go runtime ABI kind constants")
	}

	return nil
}

func fieldFits(offset, size, containerSize uint64) bool {
	return size <= containerSize && offset <= containerSize-size
}

func powerOfTwo(value uint64) bool {
	return value != 0 && value&(value-1) == 0
}

func allAtLeast(minimum uint64, values ...uint64) bool {
	for _, value := range values {
		if value < minimum {
			return false
		}
	}
	return true
}

func distinctValuesWithin(maximum uint64, values ...uint64) bool {
	seen := make(map[uint64]struct{}, len(values))
	for _, value := range values {
		if value == 0 || value > maximum {
			return false
		}
		if _, ok := seen[value]; ok {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
