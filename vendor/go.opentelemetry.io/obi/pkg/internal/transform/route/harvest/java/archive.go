// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package java // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/java"

import (
	"archive/zip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func (e *Extractor) scanDir(ctx context.Context, root string) error {
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			e.log.Debug("error walking Java classpath directory", "path", path, "error", err)
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if e.classLimitReached() || e.routeLimitReached() {
			return filepath.SkipAll
		}
		if strings.EqualFold(filepath.Ext(path), ".class") {
			if err := e.scanClassFile(ctx, path); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, filepath.SkipAll) {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		e.log.Debug("error scanning Java classpath directory", "path", root, "error", err)
	}
	return nil
}

func (e *Extractor) scanClassFile(ctx context.Context, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		e.log.Debug("error stating Java class file", "path", path, "error", err)
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if info.Size() > MaxJavaClassScanBytes {
		e.log.Info("java class file scan limit reached", "path", path, "size", info.Size(), "limit", MaxJavaClassScanBytes)
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		e.log.Debug("error reading Java class file", "path", path, "error", err)
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return e.scanClassBytes(ctx, path, data)
}

func (e *Extractor) scanArchive(ctx context.Context, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		e.log.Debug("error stating Java archive", "path", path, "error", err)
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if info.Size() > MaxJavaArchiveScanBytes {
		e.log.Info("java archive scan limit reached", "path", path, "size", info.Size(), "limit", MaxJavaArchiveScanBytes)
		return nil
	}

	reader, err := zip.OpenReader(path)
	if err != nil {
		e.log.Debug("error opening Java archive", "path", path, "error", err)
		return nil
	}
	defer func() {
		if err := reader.Close(); err != nil {
			e.log.Debug("error closing Java archive", "path", path, "error", err)
		}
	}()

	for _, file := range reader.File {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.classLimitReached() || e.routeLimitReached() {
			return nil
		}
		if !scanArchiveClassEntry(file.Name) {
			continue
		}
		if file.UncompressedSize64 > uint64(MaxJavaClassScanBytes) {
			e.log.Info("java class file scan limit reached", "path", file.Name, "size", file.UncompressedSize64, "limit", MaxJavaClassScanBytes)
			continue
		}
		if err := e.scanZipClass(ctx, path, file); err != nil {
			return err
		}
	}
	return nil
}

func scanArchiveClassEntry(name string) bool {
	name = filepath.ToSlash(name)
	if !strings.HasSuffix(name, ".class") {
		return false
	}
	if strings.HasPrefix(name, "BOOT-INF/lib/") || strings.HasPrefix(name, "WEB-INF/lib/") {
		return false
	}
	if strings.HasPrefix(name, "META-INF/") {
		return false
	}
	return true
}

func (e *Extractor) scanZipClass(ctx context.Context, archivePath string, file *zip.File) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	reader, err := file.Open()
	if err != nil {
		e.log.Debug("error opening Java class entry", "archive", archivePath, "path", file.Name, "error", err)
		return nil
	}
	defer func() {
		if err := reader.Close(); err != nil {
			e.log.Debug("error closing Java class entry", "archive", archivePath, "path", file.Name, "error", err)
		}
	}()

	data, err := io.ReadAll(io.LimitReader(reader, MaxJavaClassScanBytes+1))
	if err != nil {
		e.log.Debug("error reading Java class entry", "archive", archivePath, "path", file.Name, "error", err)
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if int64(len(data)) > MaxJavaClassScanBytes {
		e.log.Info("java class file scan limit reached", "path", file.Name, "size", len(data), "limit", MaxJavaClassScanBytes)
		return nil
	}
	return e.scanClassBytes(ctx, archivePath+":"+file.Name, data)
}

func (e *Extractor) scanClassBytes(ctx context.Context, name string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	e.classesScanned++

	class, err := parseClassFile(data)
	if err != nil {
		e.log.Debug("error parsing Java class file", "path", name, "error", err)
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	e.addRoutes(routesFromClass(class))
	return nil
}
