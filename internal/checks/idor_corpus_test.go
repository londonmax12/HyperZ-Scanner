package checks

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

func TestCorpusRingBufferBounds(t *testing.T) {
	c := NewCorpus()
	for i := 0; i < corpusParamCap*3; i++ {
		c.Ingest("user_id", strconv.Itoa(i))
	}
	got := c.ValuesForParam("user_id")
	if len(got) != corpusParamCap {
		t.Fatalf("ValuesForParam length = %d, want %d", len(got), corpusParamCap)
	}
	// Ring buffer should retain the most recent corpusParamCap entries.
	wantOldest := strconv.Itoa(corpusParamCap*3 - corpusParamCap)
	if got[0] != wantOldest {
		t.Errorf("oldest retained value = %q, want %q", got[0], wantOldest)
	}
}

func TestCorpusIngestPageWalksSinksAndPath(t *testing.T) {
	c := NewCorpus()
	p := page.Page{
		URL: "https://example.test/api/users/42?profile_id=507f1f77bcf86cd799439011",
		Forms: []page.Form{
			{
				Method: http.MethodPost,
				Action: "https://example.test/api/orders",
				Inputs: []page.FormInput{
					{Name: "order_id", Value: "1001"},
				},
			},
		},
	}
	c.IngestPage(p)
	if got := c.ValuesForParam("profile_id"); len(got) == 0 || got[0] != "507f1f77bcf86cd799439011" {
		t.Errorf("query param not ingested: %v", got)
	}
	if got := c.ValuesForParam("order_id"); len(got) == 0 || got[0] != "1001" {
		t.Errorf("form input not ingested: %v", got)
	}
	pathValues := c.ValuesForParam("__path__")
	want := map[string]bool{"api": false, "users": false, "42": false}
	for _, v := range pathValues {
		if _, ok := want[v]; ok {
			want[v] = true
		}
	}
	for v, seen := range want {
		if !seen {
			t.Errorf("path segment %q not ingested (saw %v)", v, pathValues)
		}
	}
}

func TestCorpusConcurrentIngest(t *testing.T) {
	c := NewCorpus()
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				c.Ingest(fmt.Sprintf("p%d", worker%3), fmt.Sprintf("v-%d-%d", worker, i))
			}
		}(w)
	}
	wg.Wait()
	for i := 0; i < 3; i++ {
		got := c.ValuesForParam(fmt.Sprintf("p%d", i))
		if len(got) == 0 {
			t.Errorf("param p%d had no values after concurrent ingest", i)
		}
	}
}

func TestCorpusDeterministicSnapshot(t *testing.T) {
	c := NewCorpus()
	for i := 0; i < 5; i++ {
		c.Ingest("id", strconv.Itoa(i*10))
	}
	got1 := c.ValuesForParam("id")
	got2 := c.ValuesForParam("id")
	if len(got1) != len(got2) {
		t.Fatalf("snapshot lengths differ: %d vs %d", len(got1), len(got2))
	}
	for i := range got1 {
		if got1[i] != got2[i] {
			t.Errorf("snapshot[%d] differs: %q vs %q", i, got1[i], got2[i])
		}
	}
}

func TestCorpusDuplicateValuesDoNotEvict(t *testing.T) {
	c := NewCorpus()
	for i := 0; i < corpusParamCap+5; i++ {
		// Repeat the same value over and over; ring buf dedupes.
		c.Ingest("id", "42")
	}
	got := c.ValuesForParam("id")
	if len(got) != 1 || got[0] != "42" {
		t.Errorf("duplicate ingestion should retain one value, got %v", got)
	}
}
