package main

import (
	"bytes"
	"encoding/binary"
	"errors"
)

var TPM_MAGIC = []byte{0xff, 0x54, 0x43, 0x47}

func MarshalRawQuoteMessage(rawQuoteMessage []byte) (TPMS_ATTEST, error) {
	t := TPMS_ATTEST{}
	offset := 0
	progress := 0

	t.magic = rawQuoteMessage[offset : offset+4]
	offset += 4
	if !bytes.Equal(t.magic, TPM_MAGIC) {
		return TPMS_ATTEST{}, errors.New("not a tpm signature")
	}

	t.attestationType = rawQuoteMessage[offset : offset+2]
	offset += 2
	if !bytes.Equal(t.attestationType, TPM_ST_ATTEST_QUOTE) {
		return TPMS_ATTEST{}, errors.New("selector is not TPM_ST_ATTEST_QUOTE")
	}

	t.qualifiedSigner, progress = Marshal_TPM2B_NAME(rawQuoteMessage[offset:])
	offset += progress

	t.extraData, progress = Marshal_TPM2B_DATA(rawQuoteMessage[offset:])
	offset += progress

	t.clockInfo, progress = Marshal_TPMS_CLOCK_INFO(rawQuoteMessage[offset:])
	offset += progress

	t.firmwareVersion = binary.BigEndian.Uint64(rawQuoteMessage[offset : offset+8])
	offset += 8

	t.attested, progress = Marshal_TPMU_ATTEST(rawQuoteMessage[offset:])
	offset += progress

	return t, nil
}

type TPMS_ATTEST struct {
	magic           []byte // Must always be 0xff544347. Differentiates TPM-generated structures from non-TPM structures
	attestationType TPM_ST // type of the attestation structure. Must be TPM_ST_ATTEST_QUOTE for the purposes of this program
	qualifiedSigner TPM2B_NAME
	extraData       TPM2B_DATA
	clockInfo       TPMS_CLOCK_INFO
	firmwareVersion uint64
	attested        TPMU_ATTEST
}

type TPMU_ATTEST struct {
	quote TPMS_QUOTE_INFO
	// For the purposes of this program selector: TPM_ST_ATTEST_QUOTE
}

func Marshal_TPMU_ATTEST(b []byte) (s TPMU_ATTEST, progress int) {
	s = TPMU_ATTEST{}
	s.quote, progress = Marshal_TPMS_QUOTE_INFO(b)
	return
}

type TPMS_QUOTE_INFO struct {
	pcrSelect TPML_PCR_SELECTION //information on algID, PCR selected and digest
	pcrDigest TPM2B_DIGEST       //digest of the selected PCR using the hash of the signing key
}

func Marshal_TPMS_QUOTE_INFO(b []byte) (s TPMS_QUOTE_INFO, progress int) {
	s = TPMS_QUOTE_INFO{}
	s.pcrSelect, progress = Marshal_TPML_PCR_SELECTION(b)

	e, tp := Marshal_TPM2B_DIGEST(b[progress:])
	progress += tp

	s.pcrDigest = e
	return
}

type TPM2B_DATA struct {
	size uint16 //size of the data field
	data []byte // Data
}

func Marshal_TPM2B_DATA(b []byte) (s TPM2B_DATA, progress int) {
	s = TPM2B_DATA{}

	s.size = binary.BigEndian.Uint16(b[:2])
	progress += 2

	s.data = make([]byte, s.size)
	copy(s.data, b[progress:progress+int(s.size)])
	progress += int(s.size)

	return
}

type TPML_PCR_SELECTION struct {
	count         uint32               //Number of selection structures. A value of zero is allowed.
	pcrSelections []TPMS_PCR_SELECTION //list of selections
}

func Marshal_TPML_PCR_SELECTION(b []byte) (s TPML_PCR_SELECTION, progress int) {
	s = TPML_PCR_SELECTION{}
	s.count = binary.BigEndian.Uint32(b[:4])
	progress += 4

	s.pcrSelections = make([]TPMS_PCR_SELECTION, 0)

	for i := 0; uint32(i) < s.count; i++ {
		r, p := Marshal_TPMS_PCR_SELECTION(b[progress:])
		progress += p

		s.pcrSelections = append(s.pcrSelections, r)
	}
	return
}

type TPMS_PCR_SELECTION struct {
	hashAlgorithmID []byte //the hash algorithm associated with the selection, 2 bytes long
	sizeOfSelect    uint8  // the size in octets of the pcrSelect array
	pcrSelect       []byte // selected PCRs
}

func Marshal_TPMS_PCR_SELECTION(b []byte) (s TPMS_PCR_SELECTION, progress int) {
	s = TPMS_PCR_SELECTION{}

	s.hashAlgorithmID = make([]byte, 2)
	copy(s.hashAlgorithmID, b[:2])
	progress += 2

	s.sizeOfSelect = b[progress : progress+1][0]
	progress += 1

	s.pcrSelect = make([]byte, s.sizeOfSelect)
	copy(s.pcrSelect, b[progress:progress+int(s.sizeOfSelect)])
	progress += int(s.sizeOfSelect)

	return
}

type TPMS_CLOCK_INFO struct {
	clock        uint64 // time value in milliseconds that advances while the TPM is powered
	resetCount   uint32 //number of occurrences of TPM Reset since the last TPM2_Clear()
	restartCount uint32 // number of times that TPM2_Shutdown() or _TPM_Hash_Start have occurred since the last TPM Reset or TPM2_Clear().
	safe         []byte // A value of 0 or 1. Describes if the tpm has seen a higher clock value than the current
}

func Marshal_TPMS_CLOCK_INFO(b []byte) (s TPMS_CLOCK_INFO, progress int) {
	s = TPMS_CLOCK_INFO{}

	s.clock = binary.BigEndian.Uint64(b[:8])
	progress += 8

	s.resetCount = binary.BigEndian.Uint32(b[progress : progress+4])
	progress += 4

	s.restartCount = binary.BigEndian.Uint32(b[progress : progress+4])
	progress += 4

	s.safe = make([]byte, 1)
	copy(s.safe, b[progress:progress+1])
	progress += 1

	return
}

type TPM2B_NAME struct {
	size uint16 //size of the Name structure
	name []byte // Name
}

func Marshal_TPM2B_NAME(b []byte) (s TPM2B_NAME, progress int) {
	s = TPM2B_NAME{}

	s.size = binary.BigEndian.Uint16(b[:2])
	progress += 2

	s.name = make([]byte, s.size)
	copy(s.name, b[progress:progress+int(s.size)])
	progress += int(s.size)

	return
}

type TPM2B_DIGEST struct {
	size   uint16 // Size of buffer. It cannot be bigger than sizeof(TPMU_HA)
	buffer []byte // Actual buffer
}

func Marshal_TPM2B_DIGEST(b []byte) (s TPM2B_DIGEST, progress int) {
	s = TPM2B_DIGEST{}

	s.size = binary.BigEndian.Uint16(b[:2])
	progress += 2

	s.buffer = make([]byte, s.size)
	copy(s.buffer, b[progress:progress+int(s.size)])
	progress += int(s.size)

	return
}

type TPM_ST []byte

var TPM_ST_ATTEST_QUOTE TPM_ST = []byte{0x80, 0x18}

type TPM2B_ATTEST struct {
	size                       uint16 // Size of attestationData.
	signedAttestationDataBytes []byte // The raw bytes of this is the only signed structure, size is not signed
	signedAttestationData      TPMS_ATTEST
}
