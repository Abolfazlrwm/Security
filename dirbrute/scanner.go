package main

import (
	"bufio"
	"crypto/tls"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed wordlists/common.txt
var embeddedWordlist []byte

type candidate struct {
	url string
}

type finding struct {
	url    string
	status int
	size   int64
}

// loadWordlist reads candidate path fragments from a file, or falls back
// to the list embedded in the binary when no path is given.
func loadWordlist(path string) ([]string, error) {
	var text string
	if path == "" {
		text = string(embeddedWordlist)
	} else {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read wordlist: %w", err)
		}
		text = string(data)
	}

	var words []string
	seen := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		word := strings.TrimPrefix(strings.TrimSpace(scanner.Text()), "/")
		if word == "" || strings.HasPrefix(word, "#") || seen[word] {
			continue
		}
		seen[word] = true
		words = append(words, word)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan wordlist: %w", err)
	}
	if len(words) == 0 {
		return nil, errors.New("wordlist is empty")
	}
	return words, nil
}

func newClient(cfg *config) *http.Client {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.insecureTLS},
		MaxIdleConns:        cfg.threads * 2,
		MaxIdleConnsPerHost: cfg.threads,
		IdleConnTimeout:     30 * time.Second,
	}
	return &http.Client{
		Timeout:   time.Duration(cfg.timeoutSeconds) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !cfg.followRedirect {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
	}
}

// fetch performs one GET request and returns the response status and body
// size. Bodies are capped at 8 MiB so a giant download cannot stall a worker.
func fetch(client *http.Client, cfg *config, rawURL string) (int, int64, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", cfg.userAgent)
	if cfg.cookies != "" {
		req.Header.Set("Cookie", cfg.cookies)
	}
	for _, header := range cfg.headers {
		name, value, found := strings.Cut(header, ":")
		if !found {
			return 0, 0, fmt.Errorf("malformed header %q, expected Name: Value", header)
		}
		req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()

	var size int64
	if resp.ContentLength >= 0 {
		size = resp.ContentLength
	} else {
		size, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<20))
	}
	return resp.StatusCode, size, nil
}

// wildcardBaseline probes three random paths; identical responses from all
// of them mean the server answers every request, so that exact response
// pair gets filtered out to avoid flooding the output.
func wildcardBaseline(client *http.Client, cfg *config) {
	base := strings.TrimSuffix(cfg.target, "/")
	nonces := []string{"zbq7xk1m", "p4wn9dw2", "tg6hy3vq"}

	firstStatus, firstSize, err := fetch(client, cfg, base+"/"+nonces[0])
	if err != nil {
		return
	}
	for _, nonce := range nonces[1:] {
		status, size, probeErr := fetch(client, cfg, base+"/"+nonce)
		if probeErr != nil || status != firstStatus || size != firstSize {
			return
		}
	}
	fmt.Fprintf(os.Stderr, "[!] wildcard response detected (status %d, size %d), identical responses are skipped\n", firstStatus, firstSize)
	cfg.excludePairs[statusKey(firstStatus, firstSize)] = true
}

func buildCandidates(base string, words []string, extensions []string) []candidate {
	var out []candidate
	seen := map[string]bool{}
	add := func(word string) {
		u := base + "/" + word
		if !seen[u] {
			seen[u] = true
			out = append(out, candidate{url: u})
		}
	}
	for _, word := range words {
		add(word)
		for _, ext := range extensions {
			add(word + ext)
		}
	}
	return out
}

func statusKey(status int, size int64) string {
	return fmt.Sprintf("%d:%d", status, size)
}

func keep(cfg *config, status int, size int64) bool {
	if cfg.badStatus[status] || cfg.excludeLength[size] {
		return false
	}
	return !cfg.excludePairs[statusKey(status, size)]
}

func openOutput(path string) (*os.File, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("open output file: %w", err)
	}
	return file, nil
}

func run(cfg *config) error {
	words, err := loadWordlist(cfg.wordlistPath)
	if err != nil {
		return err
	}
	client := newClient(cfg)
	wildcardBaseline(client, cfg)

	base := strings.TrimSuffix(cfg.target, "/")
	candidates := buildCandidates(base, words, cfg.extensions)
	fmt.Fprintf(os.Stderr, "[*] %d candidates queued with %d workers\n", len(candidates), cfg.threads)

	out, err := openOutput(cfg.outputPath)
	if err != nil {
		return err
	}
	if out != nil {
		defer out.Close()
	}

	var (
		jobs         = make(chan candidate)
		findings     = make(chan finding)
		scanned      atomic.Int64
		total        = len(candidates)
		workers      sync.WaitGroup
		collecting   sync.WaitGroup
		progressDone = make(chan struct{})
	)

	if !cfg.quiet {
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-progressDone:
					return
				case <-ticker.C:
					fmt.Fprintf(os.Stderr, "[*] %d/%d checked\n", scanned.Load(), total)
				}
			}
		}()
	}

	for i := 0; i < cfg.threads; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range jobs {
				if status, size, reqErr := fetch(client, cfg, job.url); reqErr == nil && keep(cfg, status, size) {
					findings <- finding{url: job.url, status: status, size: size}
				}
				scanned.Add(1)
			}
		}()
	}

	var foundCount int64
	baseForTrim := base
	collecting.Add(1)
	go func() {
		defer collecting.Done()
		for item := range findings {
			foundCount++
			line := fmt.Sprintf("%s (Status: %d) [Size: %d]\n", strings.TrimPrefix(item.url, baseForTrim+"/"), item.status, item.size)
			fmt.Print(line)
			if out != nil {
				_, _ = out.WriteString(line)
			}
		}
	}()

	go func() {
		defer close(jobs)
		for _, job := range candidates {
			jobs <- job
		}
	}()

	workers.Wait()
	close(findings)
	collecting.Wait()
	close(progressDone)

	fmt.Fprintf(os.Stderr, "[x] %d/%d checked, %d findings\n", scanned.Load(), total, foundCount)
	return nil
}
