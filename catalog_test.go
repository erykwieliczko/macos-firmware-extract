// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
)

func TestCatalogSignature(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(public)
	key := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	payload := []byte(`{"schema_version":1,"bundles":[]}`)
	signed := func(body []byte) []byte {
		data, _ := json.Marshal(map[string]string{
			"payload":   base64.StdEncoding.EncodeToString(body),
			"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload)),
		})
		return data
	}
	valid := signed(payload)
	got, err := verifyCatalog(valid, key)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("valid catalog rejected", err)
	}
	for _, data := range [][]byte{signed([]byte(`{"changed":true}`)), append(valid, []byte(`{}`)...),
		bytes.Repeat([]byte("x"), maxMetadata+1), []byte(`{"payload":"a","payload":"b","signature":"c"}`)} {
		if _, err := verifyCatalog(data, key); err == nil {
			t.Fatal("invalid catalog accepted")
		}
	}
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	der, _ = x509.MarshalPKIXPublicKey(wrong)
	key = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if _, err := verifyCatalog(valid, key); err == nil {
		t.Fatal("wrong key accepted")
	}
}
