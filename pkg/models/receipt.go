package models

// ReceiptKind tags a verdict receipt line.
type ReceiptKind string

const (
	ReceiptKEV            ReceiptKind = "KEV"
	ReceiptNuclei         ReceiptKind = "Nuclei"
	ReceiptMSF            ReceiptKind = "Metasploit"
	ReceiptEDB            ReceiptKind = "Exploit-DB"
	ReceiptPoC            ReceiptKind = "PoC"
	ReceiptEPSS           ReceiptKind = "EPSS"
	ReceiptEcosystem      ReceiptKind = "Ecosystem"
	ReceiptExposure       ReceiptKind = "Exposure"
	ReceiptDependencyPath ReceiptKind = "DependencyPath"
)

func (k ReceiptKind) String() string { return string(k) }

// VerdictReceipt is one cited line in a "FIX NOW because:" chain.
type VerdictReceipt struct {
	Kind    ReceiptKind `json:"kind"`
	Claim   string      `json:"claim"`
	URL     string      `json:"url,omitempty"`
	Details string      `json:"details,omitempty"`
}
