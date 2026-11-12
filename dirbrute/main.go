// Command dirbrute is a threaded directory and file brute-forcer for
// webservers. It requests paths built from a wordlist and reports every
// response that is not filtered out by the status code / body size rules.
//
// Only the Go standard library is used; the default wordlist is embedded
// in the binary so the compiled tool runs without any extra files.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const usageText = `dirbrute - threaded directory and file brute-forcer

Usage:
  dirbrute -u https://target/ [-w wordlist] [options]

The wordlist argument is optional: when it is omitted the common paths
embedded in the binary are used. Findings are printed to stdout, progress
and notices go to stderr, so output can be piped or parsed directly.

Options:
`

// headerList implements flag.Value so -H can be given multiple times.
type headerList []string

func (h *headerList) String() string {
	return strings.Join(*h, ", ")
}

func (h *headerList) Set(value string) error {
	if value == "" {
		return errors.New("header must not be empty")
	}
	*h = append(*h, value)
	return nil
}

type config struct {
	target         string
	wordlistPath   string
	threads        int
	extensions     []string
	badStatus      map[int]bool
	excludeLength  map[int64]bool
	excludePairs   map[string]bool
	extRaw         string
	badRaw         string
	lenRaw         string
	userAgent      string
	cookies        string
	headers        headerList
	followRedirect bool
	insecureTLS    bool
	quiet          bool
	timeoutSeconds int
	outputPath     string
}

func newFlagSet(cfg *config) *flag.FlagSet {
	fs := flag.NewFlagSet("dirbrute", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), usageText)
		fs.PrintDefaults()
	}
	fs.StringVar(&cfg.target, "u", "", "target base URL (required)")
	fs.StringVar(&cfg.wordlistPath, "w", "", "path to a wordlist file (default: embedded list)")
	fs.IntVar(&cfg.threads, "t", 20, "number of concurrent workers")
	fs.StringVar(&cfg.extRaw, "x", "", "comma separated extensions to probe, e.g. php,html")
	fs.StringVar(&cfg.badRaw, "b", "404", "comma separated status codes to ignore")
	fs.StringVar(&cfg.lenRaw, "exclude-length", "", "comma separated body sizes to ignore")
	fs.StringVar(&cfg.userAgent, "a", "dirbrute/1.1", "user agent to send with every request")
	fs.StringVar(&cfg.cookies, "c", "", "raw Cookie header to send")
	fs.Var(&cfg.headers, "H", "extra request header, repeatable (e.g. -H 'X-Forwarded-For: 10.0.0.1')")
	fs.BoolVar(&cfg.followRedirect, "r", false, "follow redirects (3xx findings are reported either way)")
	fs.BoolVar(&cfg.insecureTLS, "k", false, "skip TLS certificate verification")
	fs.BoolVar(&cfg.quiet, "q", false, "suppress progress output on stderr")
	fs.IntVar(&cfg.timeoutSeconds, "timeout", 10, "per-request timeout in seconds")
	fs.StringVar(&cfg.outputPath, "o", "", "additionally write findings to this file")
	return fs
}

func parseArgs(cfg *config, args []string) error {
	fs := newFlagSet(cfg)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if cfg.target == "" {
		return errors.New("no target URL given, use -u")
	}
	parsed, err := url.Parse(cfg.target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("invalid target URL %q, expected http(s)://host[:port]", cfg.target)
	}
	cfg.target = parsed.Scheme + "://" + parsed.Host + parsed.Path

	if cfg.threads < 1 || cfg.threads > 500 {
		return errors.New("worker count must be between 1 and 500")
	}
	if cfg.timeoutSeconds < 1 || cfg.timeoutSeconds > 600 {
		return errors.New("timeout must be between 1 and 600 seconds")
	}

	for _, ext := range strings.Split(cfg.extRaw, ",") {
		ext = strings.TrimSpace(ext)
		if ext == "" {
			continue
		}
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		cfg.extensions = append(cfg.extensions, ext)
	}

	cfg.badStatus = map[int]bool{}
	for _, code := range strings.Split(cfg.badRaw, ",") {
		code = strings.TrimSpace(code)
		if code == "" {
			continue
		}
		n, convErr := strconv.Atoi(code)
		if convErr != nil || n < 100 || n > 599 {
			return fmt.Errorf("invalid status code %q in -b", code)
		}
		cfg.badStatus[n] = true
	}

	cfg.excludeLength = map[int64]bool{}
	for _, size := range strings.Split(cfg.lenRaw, ",") {
		size = strings.TrimSpace(size)
		if size == "" {
			continue
		}
		n, convErr := strconv.ParseInt(size, 10, 64)
		if convErr != nil {
			return fmt.Errorf("invalid body size %q in -exclude-length", size)
		}
		cfg.excludeLength[n] = true
	}
	cfg.excludePairs = map[string]bool{}
	return nil
}

func main() {
	var cfg config
	if err := parseArgs(&cfg, os.Args[1:]); err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
		os.Exit(2)
	}
	if err := run(&cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
