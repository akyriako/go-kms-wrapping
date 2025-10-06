// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package opentelekomcloudkms

import (
	"context"
	"encoding/base64"
	"os"
	"reflect"
	"testing"

	kmsKeys "github.com/opentelekomcloud/gophertelekomcloud/openstack/kms/v1/keys"
)

const openTelekomCloudTestKeyId = "foo"

func TestOpenTelekomCloudKmsWrapper(t *testing.T) {
	s := NewWrapper()
	s.client = &mockOpenTelekomCloudKmsWrapperClient{}

	if _, err := s.SetConfig(context.Background()); err == nil {
		t.Fatal("expected error when OpenTelekomCloudKmsWrapper key ID is not provided")
	}

	// Set the key
	if err := os.Setenv(EnvOpenTelekomCloudKmsWrapperKeyId, openTelekomCloudTestKeyId); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Unsetenv(EnvOpenTelekomCloudKmsWrapperKeyId); err != nil {
			t.Fatal(err)
		}
	}()
	if _, err := s.SetConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOpenTelekomCloudKmsWrapper_Lifecycle(t *testing.T) {
	s := NewWrapper()
	s.client = &mockOpenTelekomCloudKmsWrapperClient{}

	if err := os.Setenv(EnvOpenTelekomCloudKmsWrapperKeyId, openTelekomCloudTestKeyId); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Unsetenv(EnvOpenTelekomCloudKmsWrapperKeyId); err != nil {
			t.Fatal(err)
		}
	}()
	if _, err := s.SetConfig(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Test Encrypt and Decrypt calls
	input := []byte("foo")
	swi, err := s.Encrypt(context.Background(), input)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	pt, err := s.Decrypt(context.Background(), swi)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
	}
}

type mockOpenTelekomCloudKmsWrapperClient struct{}

func (m *mockOpenTelekomCloudKmsWrapperClient) getRegion() string {
	return ""
}

func (m *mockOpenTelekomCloudKmsWrapperClient) getProject() string {
	return ""
}

// Encrypt is a mocked call that returns a base64 encoded string.
func (m *mockOpenTelekomCloudKmsWrapperClient) encrypt(keyId, plainText string) (encryptResponse, error) {
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(plainText)))
	base64.StdEncoding.Encode(encoded, []byte(plainText))

	output := encryptResponse{KeyId: keyId, Ciphertext: string(encoded)}
	return output, nil
}

// Decrypt is a mocked call that returns a decoded base64 string.
func (m *mockOpenTelekomCloudKmsWrapperClient) decrypt(cipherText string) (string, error) {
	decLen := base64.StdEncoding.DecodedLen(len(cipherText))
	decoded := make([]byte, decLen)
	len, err := base64.StdEncoding.Decode(decoded, []byte(cipherText))
	if err != nil {
		return "", err
	}

	if len < decLen {
		decoded = decoded[:len]
	}

	return string(decoded), nil
}

// DescribeKey is a mocked call that returns the keyID.
func (m *mockOpenTelekomCloudKmsWrapperClient) describeKey(keyID string) (*kmsKeys.Key, error) {
	return &kmsKeys.Key{KeyID: keyID}, nil
}
