//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

const messageSize = 192

type yogError struct {
	Line    int32
	Column  int32
	Message [messageSize]byte
}

// Must match YogResult in yog/include/api/yog.h field for field: the DLL writes through it.
type yogResult struct {
	Decision        int32
	_               int32
	Reason          *byte
	Trace           *byte
	MatchedLine     int32
	_               int32
	Obligations     unsafe.Pointer
	ObligationCount uintptr
}

type windowsEngine struct {
	dll        *syscall.LazyDLL
	compileFn  *syscall.LazyProc
	freeFn     *syscall.LazyProc
	checkFn    *syscall.LazyProc
	resultFree *syscall.LazyProc
}

func loadEngine(explicit string) (engine, error) {
	path := explicit
	if path == "" {
		path = os.Getenv("YOG_LIBRARY")
	}
	if path == "" {
		candidates := []string{}
		if exe, err := os.Executable(); err == nil {
			dir := filepath.Dir(exe)
			for _, root := range []string{
				filepath.Join(dir, "..", "..", ".."), // benchmarks/results/bin -> repo root
				filepath.Join(dir, "..", ".."),
			} {
				for _, build := range []string{"build-release", "build"} {
					candidates = append(candidates, filepath.Join(root, "yog", build, "yog.dll"))
				}
			}
		}
		for _, root := range []string{".", "..", "..\\.."} {
			for _, build := range []string{"build-release", "build"} {
				candidates = append(candidates, filepath.Join(root, "yog", build, "yog.dll"))
			}
		}
		for _, candidate := range candidates {
			if _, err := os.Stat(candidate); err == nil {
				path = candidate
				break
			}
		}
	}
	if path == "" {
		path = "yog.dll"
	}
	dll := syscall.NewLazyDLL(path)
	if err := dll.Load(); err != nil {
		return nil, fmt.Errorf("cannot load %q: %w", path, err)
	}
	backend := &windowsEngine{
		dll:        dll,
		compileFn:  dll.NewProc("yog_compile"),
		freeFn:     dll.NewProc("yog_free"),
		checkFn:    dll.NewProc("yog_check"),
		resultFree: dll.NewProc("yog_result_free"),
	}
	for _, proc := range []*syscall.LazyProc{
		backend.compileFn, backend.freeFn, backend.checkFn, backend.resultFree,
	} {
		if err := proc.Find(); err != nil {
			return nil, fmt.Errorf("cannot resolve %s: %w", proc.Name, err)
		}
	}
	return backend, nil
}

func (e *windowsEngine) describe() string {
	return e.dll.Name
}

func (e *windowsEngine) compile(source []byte) (unsafe.Pointer, error) {
	var failure yogError
	handle, _, callErr := e.compileFn.Call(
		uintptr(unsafe.Pointer(&source[0])),
		uintptr(len(source)),
		uintptr(unsafe.Pointer(&failure)),
	)
	if handle == 0 {
		message := cString(failure.Message[:])
		if callErr != syscall.Errno(0) && message == "" {
			return nil, callErr
		}
		return nil, fmt.Errorf("%d:%d: %s", failure.Line, failure.Column, message)
	}
	return unsafe.Pointer(handle), nil
}

func (e *windowsEngine) free(handle unsafe.Pointer) {
	e.freeFn.Call(uintptr(handle))
}

func (e *windowsEngine) check(handle unsafe.Pointer, item request) (string, error) {
	actor, err := syscall.BytePtrFromString(item.actor)
	if err != nil {
		return "", err
	}
	action, err := syscall.BytePtrFromString(item.action)
	if err != nil {
		return "", err
	}
	resource, err := syscall.BytePtrFromString(item.resource)
	if err != nil {
		return "", err
	}
	context, err := syscall.BytePtrFromString(item.context)
	if err != nil {
		return "", err
	}

	var result yogResult
	var failure yogError
	ok, _, _ := e.checkFn.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(actor)),
		uintptr(unsafe.Pointer(action)),
		uintptr(unsafe.Pointer(resource)),
		uintptr(unsafe.Pointer(context)),
		0, // trace = false
		uintptr(unsafe.Pointer(&result)),
		uintptr(unsafe.Pointer(&failure)),
	)
	defer e.resultFree.Call(uintptr(unsafe.Pointer(&result)))
	if ok == 0 {
		return "", fmt.Errorf("%s", cString(failure.Message[:]))
	}
	if result.Decision == 0 {
		return "ALLOW", nil
	}
	return "DENY", nil
}

func cString(buffer []byte) string {
	end := 0
	for end < len(buffer) && buffer[end] != 0 {
		end++
	}
	return string(buffer[:end])
}
