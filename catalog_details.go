// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const descriptionLimit = 16384
const pageLimit = 32768

type releaseDetails struct {
	ID               string `json:"id"`
	Kernel           string `json:"kernel_release"`
	Description      string `json:"description"`
	Sequence         int64  `json:"sequence"`
	CatalogSHA       string `json:"catalog_sha256"`
	InstallationHTML string `json:"installation_html,omitempty"`
	DetailsHTML      string `json:"details_html,omitempty"`
}

type detailsBundle struct {
	Schema           int             `json:"schema_version"`
	ID               string          `json:"id"`
	Flavor           string          `json:"flavor"`
	Devices          []string        `json:"devices"`
	Engine           string          `json:"engine_sha256"`
	OS               string          `json:"os_sha256"`
	SHA              string          `json:"sha256"`
	Manifest         string          `json:"manifest_sha256"`
	Size             int64           `json:"size_bytes"`
	Kernel           string          `json:"kernel_release"`
	Menu             string          `json:"menu_name"`
	URL              string          `json:"url"`
	Description      json.RawMessage `json:"description"`
	InstallationHTML json.RawMessage `json:"installation_html"`
	DetailsHTML      json.RawMessage `json:"details_html"`
}

var generationPattern = regexp.MustCompile(`^aurora-(dirtyroom|semi-dirtyroom|cleanroom)-(\d{4})[.-](\d{2})[.-](\d{2})-(\d+)$`)
var catalogHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var catalogToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)

const catalogFields = "|schema_version|kind|sequence|published_at|expires_at|bundles|id|flavor|devices|engine_sha256|os_sha256|sha256|manifest_sha256|size_bytes|kernel_release|menu_name|url|description|installation_html|details_html|"

func releaseHTML(raw json.RawMessage) (string, error) {
	if raw == nil {
		return "", nil
	}
	var page string
	if err := json.Unmarshal(raw, &page); err != nil || strings.TrimSpace(page) == "" || len(page) > pageLimit {
		return "", errors.New("invalid Aurora release HTML page")
	}
	for _, char := range page {
		if char < 32 && char != '\n' && char != '\r' && char != '\t' || char == 127 {
			return "", errors.New("invalid Aurora release HTML page")
		}
	}
	return page, nil
}

// Inspect every object before decoding structs, including unknown additive fields.
func uniqueJSON(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("Aurora catalog nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, container := token.(json.Delim)
	if !container {
		return nil
	}
	seen := make(map[string]bool)
	for decoder.More() {
		if delim == '{' {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return errors.New("duplicate or invalid Aurora catalog key")
			}
			// encoding/json otherwise treats recognized struct fields without case
			// sensitivity, unlike the Python installer's exact dictionary keys.
			lower := strings.ToLower(name)
			if name != lower && strings.Contains(catalogFields, "|"+lower+"|") {
				return errors.New("invalid case alias in Aurora catalog")
			}
			seen[name] = true
		}
		if err := uniqueJSON(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func catalogGeneration(id string) (int64, error) {
	parts := generationPattern.FindStringSubmatch(id)
	if parts == nil {
		return 0, errors.New("invalid Aurora bundle ID")
	}
	date, err := time.Parse("2006-01-02", strings.Join(parts[2:5], "-"))
	number, numberErr := strconv.ParseInt(parts[5], 10, 64)
	if err != nil || date.Year() < 1 || numberErr != nil || number <= 0 || number >= 1000000 {
		return 0, errors.New("invalid Aurora bundle date or number")
	}
	return date.Unix()/86400*1000000 + number, nil
}

// This is a read-only preview. The privileged engine pins its own verified
// selection before disk changes; opening the viewer never writes that journal.
func selectReleaseDetails(payload []byte, engine, osDigest string, minimum, now int64, requested ...string) (releaseDetails, error) {
	flavor := "semi-dirtyroom"
	if len(requested) > 0 {
		flavor = requested[0]
	}
	if flavor != "semi-dirtyroom" && flavor != "cleanroom" {
		return releaseDetails{}, errors.New("only Semi-dirtyroom and Cleanroom are offered")
	}
	invalid := errors.New("invalid, expired or incompatible Aurora release details")
	if len(payload) == 0 || len(payload) > maxMetadata || !utf8.Valid(payload) ||
		!catalogHash.MatchString(engine) || !catalogHash.MatchString(osDigest) || minimum < 1 {
		return releaseDetails{}, invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := uniqueJSON(decoder, 0); err != nil {
		return releaseDetails{}, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return releaseDetails{}, invalid
	}
	var catalog struct {
		Schema    int             `json:"schema_version"`
		Kind      string          `json:"kind"`
		Sequence  int64           `json:"sequence"`
		Published *int64          `json:"published_at"`
		Expires   *int64          `json:"expires_at"`
		Bundles   []detailsBundle `json:"bundles"`
	}
	if err := json.Unmarshal(payload, &catalog); err != nil {
		return releaseDetails{}, err
	}
	if catalog.Schema != 1 || catalog.Kind != "aurora-installer-bundles" ||
		catalog.Sequence < minimum || catalog.Published == nil || catalog.Expires == nil ||
		*catalog.Published < 0 || *catalog.Published > now+300 || *catalog.Expires <= now ||
		*catalog.Expires <= *catalog.Published || *catalog.Expires-*catalog.Published > 90*86400 ||
		len(catalog.Bundles) == 0 || len(catalog.Bundles) > 1000 {
		return releaseDetails{}, invalid
	}
	seen := make(map[string]bool)
	selected := releaseDetails{}
	var newest int64
	for _, entry := range catalog.Bundles {
		generation, err := catalogGeneration(entry.ID)
		parts := generationPattern.FindStringSubmatch(entry.ID)
		entryFlavor := ""
		if parts != nil {
			entryFlavor = parts[1]
		}
		key := entryFlavor + ":" + strconv.FormatInt(generation, 10)
		if err != nil || seen[key] || (entry.Flavor != "" && entry.Flavor != entryFlavor) || entry.Schema != 1 ||
			len(entry.Devices) != 1 || entry.Devices[0] != "apple,j700" ||
			!catalogHash.MatchString(entry.Engine) || !catalogHash.MatchString(entry.OS) ||
			!catalogHash.MatchString(entry.SHA) || !catalogHash.MatchString(entry.Manifest) ||
			entry.Size <= 0 || entry.Size > 384*1024*1024 ||
			!catalogToken.MatchString(entry.Kernel) || !catalogToken.MatchString(entry.Menu) ||
			!strings.HasPrefix(entry.URL, "https://f005.backblazeb2.com/file/omarchymacexperimental/aurora/") ||
			strings.ContainsAny(entry.URL, "?#%\\") || strings.Contains("/"+entry.URL+"/", "/../") {
			return releaseDetails{}, invalid
		}
		seen[key] = true
		description := ""
		if entry.Description != nil {
			if err := json.Unmarshal(entry.Description, &description); err != nil ||
				strings.TrimSpace(description) == "" || len(description) > descriptionLimit {
				return releaseDetails{}, invalid
			}
			for _, char := range description {
				if char < 32 && char != '\n' || char == 127 {
					return releaseDetails{}, invalid
				}
			}
		}
		if entryFlavor == flavor && entry.Engine == engine && entry.OS == osDigest && (selected.ID == "" || generation > newest) {
			newest = generation
			selected = releaseDetails{
				ID: entry.ID, Kernel: entry.Kernel, Description: description, Sequence: catalog.Sequence,
			}
		}
		installationHTML, err := releaseHTML(entry.InstallationHTML)
		if err != nil {
			return releaseDetails{}, err
		}
		detailsHTML, err := releaseHTML(entry.DetailsHTML)
		if err != nil {
			return releaseDetails{}, err
		}
		if selected.ID == entry.ID {
			selected.InstallationHTML = installationHTML
			selected.DetailsHTML = detailsHTML
		}
	}
	if selected.ID == "" {
		return releaseDetails{}, errors.New("no Aurora bundle matches this installer engine and OS image")
	}
	digest := sha256.Sum256(payload)
	selected.CatalogSHA = hex.EncodeToString(digest[:])
	return selected, nil
}

func catalogDetailsFile(input, keyPath, engine, osDigest, minimumText string, requested ...string) error {
	minimum, err := strconv.ParseInt(minimumText, 10, 64)
	if err != nil {
		return err
	}
	file, err := os.Open(input)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxMetadata+1))
	if err != nil {
		return err
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	payload, err := verifyCatalog(data, key)
	if err != nil {
		return err
	}
	details, err := selectReleaseDetails(payload, engine, osDigest, minimum, time.Now().Unix(), requested...)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(details)
}
