package tool

// Documented in https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf

// TPMS_ATTEST
type TPMSAttest struct {
	Magic           magic `json:"-"`
	AttestationType tpmSt
	QualifiedSigner tpm2bName
	ExtraData       tpm2bData
	ClockInfo       tpmsClockInfo
	FirmwareVersion uint64
	Attested        tpMuAttest
}

const (
	// TPM_GENERATED
	tpmGeneratedValue magic = 0xff544347
	// TPM_ST_ATTEST_QUOTE of type TPM_ST
	tpmStAttestQuote tpmSt = 0x8018
)

// The magic value differentiates TPM-generated structures from non-TPM structures
type magic uint32

// TPM_ST
type tpmSt uint16

// TPM2B_NAME
type tpm2bName struct {
	Size uint16 `json:"-"` // Size of the Name field
	Name []byte
}

// TPM2B_DATA
type tpm2bData struct {
	Size uint16 `json:"-"` // Size of the Data field
	Data []byte
}

// TPMS_CLOCK_INFO
type tpmsClockInfo struct {
	Clock        uint64    // Time value in milliseconds that advances while the TPM is powered
	ResetCount   uint32    // Number of occurrences of TPM Reset since the last TPM2_Clear()
	RestartCount uint32    // Number of times that TPM2_Shutdown() or _TPM_Hash_Start have occurred since the last TPM Reset or TPM2_Clear()
	Safe         tpMiYesNo // A value of 0 or 1. Describes if the tpm has seen a higher clock value than the current
}

// TPMI_YES_NO
type tpMiYesNo uint8

// TPMU_ATTEST
type tpMuAttest struct {
	Quote tpmsQuoteInfo
	// For the purposes of this program selector: TPM_ST_ATTEST_QUOTE
}

// TPMS_QUOTE_INFO
type tpmsQuoteInfo struct {
	PcrSelect tpmlPcrSelection // Information on algID, PCR selected and digest
	PcrDigest tpm2bDigest      // Digest of the selected PCR using the hash of the signing key
}

// TPML_PCR_SELECTION
type tpmlPcrSelection struct {
	Count         uint32             // Number of PcrSelections. A value of zero is allowed.
	PcrSelections []tpmsPcrSelection // List of selections
}

// TPM2B_DIGEST
type tpm2bDigest struct {
	Size   uint16 `json:"-"` // Size of Buffer
	Buffer []byte // Actual buffer
}

type pcrSelect []byte

// TPMS_PCR_SELECTION
type tpmsPcrSelection struct {
	HashAlgorithm tpmAlg    // Hash algorithm associated with the selection
	SizeOfSelect  uint8     // Size of the PcrSelect array
	PcrSelect     pcrSelect // Selected PCRs
}

// TPM_ALG
type tpmAlg uint16

const (
	tpmAlgSha1   tpmAlg = 0x04 // TPM_ALG_SHA1
	tpmAlgSha256 tpmAlg = 0x0B // TPM_ALG_SHA256
	tpmAlgSha384 tpmAlg = 0x0C // TPM_ALG_SHA384
	tpmAlgSha512 tpmAlg = 0x0D // TPM_ALG_SHA512
	tpmAlgSm3256 tpmAlg = 0x12 // TPM_ALG_SM3_256
)
