// In-process OPA harness for the fair cross-engine comparison.
//
// `opa eval` per request measures process startup.  This program uses the Go
// SDK: it loads the policy and data once (PrepareForEval), then evaluates the
// pre-compiled query per request.  That is the same boundary as `yog_check`
// after compilation and as the Cedar SDK harness.
//
// Usage:
//   opa-bench --data data.json --policy policy.rego --requests requests.tsv
//             [--iterations N] [--warmup N] [--mode load|warm]
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

type request struct {
	label    string
	actor    string
	resource string
}

type sampleOut struct {
	Label     string  `json:"label"`
	Decision  string  `json:"decision"`
	SamplesNs []int64 `json:"samples_ns"`
}

func main() {
	dataPath := flag.String("data", "", "data.json")
	policyPath := flag.String("policy", "", "policy.rego")
	requestsPath := flag.String("requests", "", "requests.tsv")
	iterations := flag.Int("iterations", 5000, "timed evaluations per request")
	warmup := flag.Int("warmup", 100, "untimed evaluations per request")
	mode := flag.String("mode", "warm", "load or warm")
	flag.Parse()

	if *policyPath == "" || *dataPath == "" {
		fmt.Fprintln(os.Stderr, "--data and --policy are required")
		os.Exit(2)
	}

	ctx := context.Background()
	dataBody, err := os.ReadFile(*dataPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "data error: %v\n", err)
		os.Exit(1)
	}
	store := inmem.NewFromReader(bytes.NewReader(dataBody))

	policyBody, err := os.ReadFile(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "policy error: %v\n", err)
		os.Exit(1)
	}

	loadStarted := nowNs()
	module, err := ast.ParseModule(*policyPath, string(policyBody))
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse error: %v\n", err)
		os.Exit(1)
	}
	prepared, err := rego.New(
		rego.Query("data.yogbench.decision"),
		rego.ParsedModule(module),
		rego.Store(store),
	).PrepareForEval(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "prepare error: %v\n", err)
		os.Exit(1)
	}
	loadNs := nowNs() - loadStarted

	if *mode == "load" {
		fmt.Printf("{\"mode\":\"load\",\"prepare_ns\":%d}\n", loadNs)
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
		input := map[string]interface{}{
			"actor":    item.actor,
			"resource": item.resource,
		}

		decision := ""
		for i := 0; i < *warmup; i++ {
			decision, err = evaluate(ctx, prepared, input)
			if err != nil {
				fmt.Fprintf(os.Stderr, "evaluation error: %v\n", err)
				os.Exit(1)
			}
		}
		if *warmup == 0 {
			decision, err = evaluate(ctx, prepared, input)
			if err != nil {
				fmt.Fprintf(os.Stderr, "evaluation error: %v\n", err)
				os.Exit(1)
			}
		}

		samples := make([]int64, 0, *iterations)
		for i := 0; i < *iterations; i++ {
			started := nowNs()
			decision, err = evaluate(ctx, prepared, input)
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

func evaluate(ctx context.Context, prepared rego.PreparedEvalQuery,
	input map[string]interface{}) (string, error) {
	results, err := prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return "", err
	}
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return "", fmt.Errorf("no decision in result set")
	}
	text, ok := results[0].Expressions[0].Value.(string)
	if !ok {
		return "", fmt.Errorf("decision is not a string: %T", results[0].Expressions[0].Value)
	}
	return text, nil
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
		items = append(items, request{
			label:    fields[0],
			actor:    fields[1],
			resource: fields[3],
		})
	}
	return items, nil
}
