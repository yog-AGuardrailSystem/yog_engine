// In-process YOG harness for the fair cross-engine comparison.
//
// This is a Go binding over the public C ABI: it loads the YOG shared library
// once, compiles the policy once, then calls yog_check in a loop.  That is the
// same runtime boundary as the OPA Go SDK harness (`opa-bench`), which prepares
// the Rego query once and evaluates it in process.  Every decision crosses the
// Go -> C boundary, which is part of what this harness measures; the OPA
// harness crosses no such boundary because OPA is written in Go.  Read the two
// columns together, not as a pure engine comparison.
//
// The binding is implemented with syscall on Windows and cgo elsewhere.  Both
// call exactly the same public functions.
//
// Usage:
//   yog-go-bench --policy P --requests R [--iterations N] [--warmup N]
//                [--mode load|warm] [--library PATH]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"unsafe"
)

type sampleOut struct {
	Label     string  `json:"label"`
	Decision  string  `json:"decision"`
	SamplesNs []int64 `json:"samples_ns"`
}

type request struct {
	label    string
	actor    string
	action   string
	resource string
	context  string
}

type engine interface {
	compile(source []byte) (unsafe.Pointer, error)
	free(handle unsafe.Pointer)
	check(handle unsafe.Pointer, item request) (string, error)
	describe() string
}

func main() {
	policyPath := flag.String("policy", "", "policy source file")
	requestsPath := flag.String("requests", "", "tab-separated requests")
	iterations := flag.Int("iterations", 5000, "timed evaluations per request")
	warmup := flag.Int("warmup", 100, "untimed evaluations per request")
	mode := flag.String("mode", "warm", "load or warm")
	libraryPath := flag.String("library", "", "path to YOG shared library")
	flag.Parse()

	if *policyPath == "" {
		fmt.Fprintln(os.Stderr, "--policy is required")
		os.Exit(2)
	}

	backend, err := loadEngine(*libraryPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "library error: %v\n", err)
		os.Exit(1)
	}

	source, err := os.ReadFile(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "policy error: %v\n", err)
		os.Exit(1)
	}

	loadStarted := nowNs()
	handle, compileErr := backend.compile(source)
	loadNs := nowNs() - loadStarted
	if compileErr != nil {
		fmt.Fprintf(os.Stderr, "compile error: %v\n", compileErr)
		os.Exit(1)
	}
	defer backend.free(handle)

	if *mode == "load" {
		payload := map[string]any{
			"mode":       "load",
			"compile_ns": loadNs,
			"library":    backend.describe(),
			"go_version": runtime.Version(),
		}
		encoded, _ := json.Marshal(payload)
		fmt.Println(string(encoded))
		return
	}

	if *requestsPath == "" {
		fmt.Fprintln(os.Stderr, "--requests is required for warm mode")
		os.Exit(2)
	}
	requests, err := readRequests(*requestsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "requests error: %v\n", err)
		os.Exit(1)
	}

	encoder := json.NewEncoder(os.Stdout)
	for _, item := range requests {
		decision := ""
		for i := 0; i < *warmup; i++ {
			decision, err = backend.check(handle, item)
			if err != nil {
				fmt.Fprintf(os.Stderr, "evaluation error: %v\n", err)
				os.Exit(1)
			}
		}
		if *warmup == 0 {
			decision, err = backend.check(handle, item)
			if err != nil {
				fmt.Fprintf(os.Stderr, "evaluation error: %v\n", err)
				os.Exit(1)
			}
		}

		samples := make([]int64, 0, *iterations)
		for i := 0; i < *iterations; i++ {
			started := nowNs()
			decision, err = backend.check(handle, item)
			if err != nil {
				fmt.Fprintf(os.Stderr, "evaluation error: %v\n", err)
				os.Exit(1)
			}
			samples = append(samples, nowNs()-started)
		}

		if err := encoder.Encode(sampleOut{
			Label:     item.label,
			Decision:  decision,
			SamplesNs: samples,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "encode error: %v\n", err)
			os.Exit(1)
		}
	}
}

func readRequests(path string) ([]request, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var items []request
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 4 {
			return nil, fmt.Errorf("malformed line: %q", line)
		}
		item := request{
			label:    fields[0],
			actor:    fields[1],
			action:   fields[2],
			resource: fields[3],
		}
		if len(fields) > 4 {
			item.context = fields[4]
		}
		items = append(items, item)
	}
	return items, nil
}
