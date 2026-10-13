// SPDX-License-Identifier: MIT
package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func detailsFixture() map[string]any {
	return map[string]any{
		"schema_version": 1, "kind": "aurora-installer-bundles", "sequence": 7,
		"published_at": 1000, "expires_at": 2000,
		"bundles": []any{map[string]any{
			"schema_version": 1, "id": "aurora-semi-dirtyroom-2026.10.07-9", "flavor": "semi-dirtyroom",
			"devices": []string{"apple,j700"}, "engine_sha256": strings.Repeat("a", 64),
			"os_sha256": strings.Repeat("b", 64), "sha256": strings.Repeat("c", 64),
			"manifest_sha256": strings.Repeat("d", 64), "size_bytes": 123,
			"kernel_release": "7.1.12-test", "menu_name": "aurora-test",
			"url":         "https://f005.backblazeb2.com/file/omarchymacexperimental/aurora/test.tar.zst",
			"description": "Semi-dirtyroom Neo — 2026.10.07\nKernel j700; Mesa agx3",
		}},
	}
}

func checkDetails(value map[string]any) (releaseDetails, error) {
	payload, _ := json.Marshal(value)
	return selectReleaseDetails(payload, strings.Repeat("a", 64), strings.Repeat("b", 64), 7, 1500)
}

func TestDetailsCompatibilityAndNumericOrder(t *testing.T) {
	value := detailsFixture()
	entry := value["bundles"].([]any)[0].(map[string]any)
	copyEntry := func(id, osDigest string) map[string]any {
		copy := make(map[string]any)
		for name, field := range entry {
			copy[name] = field
		}
		copy["id"], copy["os_sha256"] = id, osDigest
		return copy
	}
	value["bundles"] = append(value["bundles"].([]any),
		copyEntry("aurora-semi-dirtyroom-2026.10.08-1", strings.Repeat("f", 64)),
		copyEntry("aurora-semi-dirtyroom-2026.10.07-10", strings.Repeat("b", 64)))
	details, err := checkDetails(value)
	if err != nil || details.ID != "aurora-semi-dirtyroom-2026.10.07-10" || details.Description != entry["description"] {
		t.Fatal("did not select the newest compatible described build", details, err)
	}
	delete(entry, "description")
	value["bundles"] = []any{entry}
	if details, err := checkDetails(value); err != nil || details.Description != "" {
		t.Fatal("legacy description fallback failed", details, err)
	}
}

func TestDetailsRetainsBothHTMLPagesAndRejectsInvalidPages(t *testing.T) {
	for _, name := range []string{"installation_html", "details_html"} {
		value := detailsFixture()
		entry := value["bundles"].([]any)[0].(map[string]any)
		page := "<h1>Hardware</h1>\n\t<p>Audio: experimental</p>"
		entry[name] = page
		details, err := checkDetails(value)
		if err != nil || name == "installation_html" && details.InstallationHTML != page || name == "details_html" && details.DetailsHTML != page {
			t.Fatal("HTML page was not retained", details, err)
		}
		for _, bad := range []any{nil, 123, "", " ", "bad\x00", "bad\x1b", strings.Repeat("é", 16385)} {
			entry[name] = bad
			if _, err := checkDetails(value); err == nil {
				t.Fatal("invalid HTML page accepted", name)
			}
		}
	}
}

func TestDetailsRejectMalformedCatalog(t *testing.T) {
	for _, key := range []string{"OS_SHA256", "ENGINE_SHA256", "Description", "ID"} {
		value := detailsFixture()
		entry := value["bundles"].([]any)[0].(map[string]any)
		entry[key] = entry[strings.ToLower(key)]
		if _, err := checkDetails(value); err == nil {
			t.Fatal("case-insensitive field alias accepted", key)
		}
	}
	for name, field := range map[string]any{
		"schema_version": 2, "sequence": 6, "published_at": nil,
		"expires_at": 1499, "kind": "other", "bundles": []any{},
	} {
		value := detailsFixture()
		value[name] = field
		if _, err := checkDetails(value); err == nil {
			t.Fatal("bad catalog accepted", name)
		}
	}
	for name, field := range map[string]any{
		"description": nil, "id": "aurora-semi-dirtyroom-2026.02.30-1",
		"devices": []string{"apple,j614s"}, "size_bytes": true,
		"engine_sha256": strings.Repeat("f", 64), "url": "https://attacker.invalid/",
	} {
		value := detailsFixture()
		value["bundles"].([]any)[0].(map[string]any)[name] = field
		if _, err := checkDetails(value); err == nil {
			t.Fatal("bad bundle accepted", name)
		}
	}
	for _, description := range []string{"", " ", "bad\x1b[31m", "bad\x00", "bad\t", strings.Repeat("é", 8193)} {
		value := detailsFixture()
		value["bundles"].([]any)[0].(map[string]any)["description"] = description
		if _, err := checkDetails(value); err == nil {
			t.Fatal("unsafe or oversized description accepted")
		}
	}
	value := detailsFixture()
	value["bundles"] = append(value["bundles"].([]any), value["bundles"].([]any)[0])
	if _, err := checkDetails(value); err == nil {
		t.Fatal("duplicate generation accepted")
	}
	data, _ := json.Marshal(detailsFixture())
	data = []byte(strings.Replace(string(data), `"sequence":7`, `"sequence":7,"sequence":8`, 1))
	if _, err := selectReleaseDetails(data, strings.Repeat("a", 64), strings.Repeat("b", 64), 7, 1500); err == nil {
		t.Fatal("duplicate payload key accepted")
	}
}

func TestDetailsOffersOnlySemiDirtyroom(t *testing.T) {
	value := detailsFixture()
	semi := value["bundles"].([]any)[0].(map[string]any)
	// Historical catalogs may still list a retired Dirtyroom bundle.
	legacy := make(map[string]any)
	for name, field := range semi {
		legacy[name] = field
	}
	legacy["id"] = "aurora-dirtyroom-2026.10.08-1"
	delete(legacy, "flavor")
	value["bundles"] = append(value["bundles"].([]any), legacy)
	payload, _ := json.Marshal(value)
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	for _, requested := range [][]string{nil, {"semi-dirtyroom"}} {
		details, err := selectReleaseDetails(payload, a, b, 7, 1500, requested...)
		if err != nil || details.ID != "aurora-semi-dirtyroom-2026.10.07-9" {
			t.Fatal(requested, details, err)
		}
	}
	for _, flavor := range []string{"dirtyroom", "cleanroom", "unknown"} {
		if _, err := selectReleaseDetails(payload, a, b, 7, 1500, flavor); err == nil {
			t.Fatal("unavailable choice accepted", flavor)
		}
	}
	// Cleanroom is offered: its own bundle is selected, never a Semi-dirtyroom one.
	clean := map[string]any{}
	for key, item := range semi {
		clean[key] = item
	}
	clean["id"], clean["flavor"], clean["menu_name"] = "aurora-cleanroom-2026.10.12-1", "cleanroom", "aurora-cleanroom-2026.10.12-1"
	withClean := map[string]any{}
	for key, item := range value {
		withClean[key] = item
	}
	withClean["bundles"] = []any{semi, clean}
	cleanPayload, _ := json.Marshal(withClean)
	if details, err := selectReleaseDetails(cleanPayload, a, b, 7, 1500, "cleanroom"); err != nil || details.ID != "aurora-cleanroom-2026.10.12-1" {
		t.Fatal("cleanroom details", details, err)
	}
	if details, err := selectReleaseDetails(cleanPayload, a, b, 7, 1500, "semi-dirtyroom"); err != nil || details.ID == "aurora-cleanroom-2026.10.12-1" {
		t.Fatal("semi-dirtyroom details", details, err)
	}
	value["bundles"] = []any{legacy}
	payload, _ = json.Marshal(value)
	if _, err := selectReleaseDetails(payload, a, b, 7, 1500); err == nil {
		t.Fatal("selected a retired Dirtyroom bundle")
	}
	semi["flavor"] = "dirtyroom"
	value["bundles"] = []any{semi}
	payload, _ = json.Marshal(value)
	if _, err := selectReleaseDetails(payload, a, b, 7, 1500); err == nil {
		t.Fatal("inconsistent signed flavor accepted")
	}
}
