package models

import "testing"

func TestReceiptKindString(t *testing.T) {
	if ReceiptKEV.String() != "KEV" {
		t.Fatalf("got %q", ReceiptKEV.String())
	}
}
