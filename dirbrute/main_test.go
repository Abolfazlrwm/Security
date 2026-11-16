package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseArgsValid(t *testing.T) {
	var cfg config
	if err := parseArgs(&cfg, []string{"-u", "https://target/", "-t", "30", "-x", "php,html"}); err != nil {
		t.Fatalf("valid args rejected: %v", err)
	}
	if cfg.target != "https://target/" {
		t.Errorf("target = %q, want https://target/", cfg.target)
	}
	if cfg.threads != 30 {
		t.Errorf("threads = %d, want 30", cfg.threads)
	}
	want := []string{".php", ".html"}
	if !reflect.DeepEqual(cfg.extensions, want) {
		t.Errorf("extensions = %v, want %v (dot must be added automatically)", cfg.extensions, want)
	}
}

func TestParseArgsDefaults(t *testing.T) {
	var cfg config
	if err := parseArgs(&cfg, []string{"-u", "http://127.0.0.1:8080/"}); err != nil {
		t.Fatalf("default args rejected: %v", err)
	}
	if cfg.threads != 20 {
		t.Errorf("threads default = %d, want 20", cfg.threads)
	}
	if cfg.timeoutSeconds != 10 {
		t.Errorf("timeout default = %d, want 10", cfg.timeoutSeconds)
	}
	if cfg.userAgent != "dirbrute/1.1.1" {
		t.Errorf("user agent default = %q, want dirbrute/1.1.1", cfg.userAgent)
	}
	if !cfg.badStatus[404] {
		t.Errorf("404 must be excluded by default")
	}
}

func TestParseArgsErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"missing target", []string{}},
		{"bare host without scheme", []string{"-u", "example.com"}},
		{"unsupported scheme", []string{"-u", "ftp://example.com/"}},
		{"zero workers", []string{"-u", "https://t/", "-t", "0"}},
		{"too many workers", []string{"-u", "https://t/", "-t", "501"}},
		{"zero timeout", []string{"-u", "https://t/", "-timeout", "0"}},
		{"huge timeout", []string{"-u", "https://t/", "-timeout", "601"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cfg config
			if err := parseArgs(&cfg, tc.args); err == nil {
				t.Errorf("%s: expected an error, got none", tc.name)
			}
		})
	}
}

func TestLoadWordlistFromFile(t *testing.T) {
	content := "# comment line\n/admin\n\napi\n/repeated\nrepeated\n# another\n"
	path := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	words, err := loadWordlist(path)
	if err != nil {
		t.Fatalf("loadWordlist: %v", err)
	}
	want := []string{"admin", "api", "repeated"}
	if !reflect.DeepEqual(words, want) {
		t.Errorf("words = %v, want %v (comments, blanks, dupes and leading slashes must be handled)", words, want)
	}
}

func TestLoadWordlistEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadWordlist(path); err == nil {
		t.Fatal("expected an error for an empty wordlist")
	}
}

func TestLoadWordlistMissingFile(t *testing.T) {
	_, err := loadWordlist(filepath.Join(t.TempDir(), "nope.txt"))
	if err == nil || !strings.Contains(err.Error(), "read wordlist") {
		t.Fatalf("expected a read error, got %v", err)
	}
}

func TestLoadWordlistEmbeddedFallback(t *testing.T) {
	words, err := loadWordlist("")
	if err != nil {
		t.Fatalf("embedded list failed: %v", err)
	}
	if len(words) < 50 {
		t.Errorf("embedded wordlist has %d entries, expected at least 50", len(words))
	}
	for _, wanted := range []string{"admin", "robots.txt", ".env"} {
		found := false
		for _, w := range words {
			if w == wanted {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("embedded wordlist is missing %q", wanted)
		}
	}
}

func TestBuildCandidates(t *testing.T) {
	base := "http://t"
	got := buildCandidates(base, []string{"admin", "api"}, []string{".php"})
	want := []string{"http://t/admin", "http://t/admin.php", "http://t/api", "http://t/api.php"}
	if len(got) != len(want) {
		t.Fatalf("got %d candidates, want %d", len(got), len(want))
	}
	for i, c := range got {
		if c.url != want[i] {
			t.Errorf("candidate %d = %q, want %q", i, c.url, want[i])
		}
	}
}

func TestBuildCandidatesDeduplicates(t *testing.T) {
	got := buildCandidates("http://t", []string{"api", "api"}, nil)
	if len(got) != 1 {
		t.Errorf("duplicate words must collapse, got %d candidates", len(got))
	}
}

func TestKeepFiltering(t *testing.T) {
	cfg := &config{
		badStatus:     map[int]bool{404: true},
		excludeLength: map[int64]bool{0: true},
		excludePairs:  map[string]bool{"200:335": true},
	}
	cases := []struct {
		status int
		size   int64
		want   bool
		why    string
	}{
		{200, 124, true, "ordinary hit is kept"},
		{404, 555, false, "excluded status is dropped"},
		{200, 0, false, "excluded length is dropped"},
		{200, 335, false, "wildcard baseline pair is dropped"},
		{301, 99, true, "redirect with different pair is kept"},
	}
	for _, tc := range cases {
		if got := keep(cfg, tc.status, tc.size); got != tc.want {
			t.Errorf("keep(%d, %d) = %v, want %v (%s)", tc.status, tc.size, got, tc.want, tc.why)
		}
	}
}

func TestStatusKey(t *testing.T) {
	if got, want := statusKey(200, int64(124)), "200:124"; got != want {
		t.Errorf("statusKey = %q, want %q", got, want)
	}
}
