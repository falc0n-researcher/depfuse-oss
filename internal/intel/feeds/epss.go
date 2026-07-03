package feeds

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

const epssURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

// EPSS ingests FIRST EPSS daily scores.
type EPSS struct {
	lastBodySHA string
}

func (f *EPSS) Name() string { return "EPSS" }

// LastBodySHA returns the hash of the last fetched gzip payload.
func (f *EPSS) LastBodySHA() string { return f.lastBodySHA }

func (f *EPSS) Fetch(ctx context.Context, runID string) ([]intel.NormalizedRecord, error) {
	status, body, err := FetchHTTPStatus(ctx, epssURL)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, fmt.Errorf("epss http %d", status)
	}

	bodySHA := EPSSBodySHA(body)
	f.lastBodySHA = bodySHA
	if prev := epssPreviousHash(ctx); prev != "" && prev == bodySHA {
		return nil, fmt.Errorf("%w (%s)", ErrUnchanged, bodySHA)
	}

	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	records, err := parseEPSSCSV(gz, runID)
	if err != nil {
		return nil, err
	}
	return records, nil
}

func parseEPSSCSV(r io.Reader, runID string) ([]intel.NormalizedRecord, error) {
	data, err := stripEPSSComments(r)
	if err != nil {
		return nil, err
	}

	cr := csv.NewReader(bytes.NewReader(data))
	cr.FieldsPerRecord = -1

	now := time.Now().UTC()
	var out []intel.NormalizedRecord
	for {
		row, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("epss csv: %w", err)
		}
		if len(row) < 2 {
			continue
		}
		cve := strings.TrimSpace(row[0])
		if cve == "" || strings.EqualFold(cve, "cve") || strings.HasPrefix(cve, "#") {
			continue
		}
		if !strings.HasPrefix(cve, "CVE-") {
			continue
		}
		score, err := strconv.ParseFloat(strings.TrimSpace(row[1]), 64)
		if err != nil {
			continue
		}
		sc := score
		out = append(out, intel.NormalizedRecord{
			CanonicalID: cve,
			Aliases:     []intel.AliasInput{{Alias: cve, AliasType: "CVE"}},
			Artifact: intel.ArtifactInput{
				ID: "EPSS:" + cve, Source: models.SourceEPSS, TrustClass: models.TrustMedium,
				Title: "EPSS score", ObservedAt: now, FeedRunID: runID, EPSSScore: &sc,
			},
		})
	}
	return out, nil
}

func stripEPSSComments(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
