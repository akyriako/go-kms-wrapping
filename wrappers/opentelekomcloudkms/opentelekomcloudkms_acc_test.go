// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package opentelekomcloudkms

import (
	"context"
	"os"
	"reflect"
	"testing"
)

// This test executes real calls. The calls themselves should be free,
// but the KMS key used is generally not free. Please see the document
// of Open Telekom Cloud to get the price of KMS.
//
// To run this test, the following env variables need to be set:
//   - VAULT_OPENTELEKOMCLOUDKMS_KEY_ID or OPENTELEKOMCLOUDKMS_WRAPPER_KEY_ID
//   - OPENTELEKOMCLOUD_REGION
//   - OPENTELEKOMCLOUD_PROJECT
//   - OPENTELEKOMCLOUD_ACCESS_KEY
//   - OPENTELEKOMCLOUD_SECRET_KEY
func TestAccOpenTelekomCloudKmsWrapper_Lifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}

	s := NewWrapper()
	_, err := s.SetConfig(context.Background())
	if err != nil {
		t.Fatalf("err : %s", err)
	}

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
