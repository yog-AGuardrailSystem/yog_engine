//go:build !windows

package main

/*
#cgo CFLAGS: -I${SRCDIR}/../../../yog/include/api
#cgo LDFLAGS: -L${SRCDIR}/../../../yog/build-release -lyog -Wl,-rpath,${SRCDIR}/../../../yog/build-release
#include <stdlib.h>
#include <stdbool.h>
#include "yog.h"
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

type cgoEngine struct{}

func loadEngine(explicit string) (engine, error) {
	// With cgo the library is linked and loaded by the OS loader.  The explicit
	// path is only used to fail early with a useful message.
	path := explicit
	if path == "" {
		path = os.Getenv("YOG_LIBRARY")
	}
	if path != "" {
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("cannot open %q: %w", path, err)
		}
	}
	return &cgoEngine{}, nil
}

func (e *cgoEngine) describe() string {
	return "cgo-linked libyog"
}

func (e *cgoEngine) compile(source []byte) (unsafe.Pointer, error) {
	text := C.CString(string(source))
	defer C.free(unsafe.Pointer(text))
	var failure C.YogError
	handle := C.yog_compile(text, C.size_t(len(source)), &failure)
	if handle == nil {
		return nil, fmt.Errorf("%d:%d: %s",
			int(failure.line), int(failure.column), C.GoString(&failure.message[0]))
	}
	return unsafe.Pointer(handle), nil
}

func (e *cgoEngine) free(handle unsafe.Pointer) {
	C.yog_free((*C.Yog)(handle))
}

func (e *cgoEngine) check(handle unsafe.Pointer, item request) (string, error) {
	actor := C.CString(item.actor)
	defer C.free(unsafe.Pointer(actor))
	action := C.CString(item.action)
	defer C.free(unsafe.Pointer(action))
	resource := C.CString(item.resource)
	defer C.free(unsafe.Pointer(resource))
	context := C.CString(item.context)
	defer C.free(unsafe.Pointer(context))

	var result C.YogResult
	var failure C.YogError
	ok := C.yog_check((*C.Yog)(handle), actor, action, resource, context,
		C.bool(false), &result, &failure)
	defer C.yog_result_free(&result)
	if !ok {
		return "", fmt.Errorf("%s", C.GoString(&failure.message[0]))
	}
	if result.decision == C.YOG_ALLOW {
		return "ALLOW", nil
	}
	return "DENY", nil
}
