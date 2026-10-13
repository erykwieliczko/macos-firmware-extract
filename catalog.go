// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
)

func verifyCatalog(data, key []byte) ([]byte, error) {
	if len(data) == 0 || len(data) > maxMetadata {
		return nil, errors.New("invalid Aurora catalog size")
	}
	// Decode fields explicitly to reject duplicate envelope keys.
	decoder := json.NewDecoder(bytes.NewReader(data))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("invalid Aurora catalog envelope")
	}
	fields := make(map[string]string)
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || (name != "payload" && name != "signature") {
			return nil, errors.New("invalid Aurora catalog field")
		}
		if _, exists := fields[name]; exists {
			return nil, errors.New("duplicate Aurora catalog field")
		}
		var value string
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		fields[name] = value
	}
	if _, err := decoder.Token(); err != nil || len(fields) != 2 {
		return nil, errors.New("incomplete Aurora catalog envelope")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("trailing Aurora catalog data")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(fields["payload"])
	if err != nil || len(payload) == 0 {
		return nil, errors.New("invalid Aurora catalog payload")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(fields["signature"])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, errors.New("invalid Aurora catalog signature")
	}
	block, rest := pem.Decode(key)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid Aurora catalog public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	public, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || !ed25519.Verify(public, payload, signature) {
		return nil, errors.New("Aurora catalog signature verification failed")
	}
	return payload, nil
}

func verifyCatalogFile(input, keyPath string) error {
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
	_, err = os.Stdout.Write(payload)
	return err
}
