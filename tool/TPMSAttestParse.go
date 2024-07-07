package tool

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

func parseRawQuoteMessage(rawQuoteMessage []byte) (t TPMSAttest, err error) {
	defer func() {
		if r := recover(); r != nil {
			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("unknown panic")
			}
		}
	}()

	reader := bytes.NewReader(rawQuoteMessage)

	t = TPMSAttest{}

	// Magic
	if err = binary.Read(reader, binary.BigEndian, &t.Magic); err != nil {
		return TPMSAttest{}, fmt.Errorf("could not read magic field: %w", err)
	}
	if t.Magic != tpmGeneratedValue {
		return TPMSAttest{}, fmt.Errorf("magic field mismatch: got %x, want %x", t.Magic, tpmGeneratedValue)
	}

	// AttestationType
	if err = binary.Read(reader, binary.BigEndian, &t.AttestationType); err != nil {
		return TPMSAttest{}, fmt.Errorf("could not read attestationType field: %w", err)
	}
	if t.AttestationType != tpmStAttestQuote {
		return TPMSAttest{}, errors.New("unsupported attestation type")
	}

	// QualifiedSigner
	if err = binary.Read(reader, binary.BigEndian, &t.QualifiedSigner.Size); err != nil {
		return TPMSAttest{}, fmt.Errorf("could not read qualifiedSigner size: %w", err)
	}
	t.QualifiedSigner.Name = make([]byte, t.QualifiedSigner.Size)
	if err = binary.Read(reader, binary.BigEndian, &t.QualifiedSigner.Name); err != nil {
		return TPMSAttest{}, fmt.Errorf("could not read qualifiedSigner name: %w", err)
	}

	// ExtraData
	if err = binary.Read(reader, binary.BigEndian, &t.ExtraData.Size); err != nil {
		return TPMSAttest{}, fmt.Errorf("could not read extraData size: %w", err)
	}
	t.ExtraData.Data = make([]byte, t.ExtraData.Size)
	if err = binary.Read(reader, binary.BigEndian, &t.ExtraData.Data); err != nil {
		return TPMSAttest{}, fmt.Errorf("could not read extraData data: %w", err)
	}

	// ClockInfo
	if err = binary.Read(reader, binary.BigEndian, &t.ClockInfo); err != nil {
		return TPMSAttest{}, fmt.Errorf("could not read clockInfo: %w", err)
	}

	// FirmwareVersion
	if err = binary.Read(reader, binary.BigEndian, &t.FirmwareVersion); err != nil {
		return TPMSAttest{}, fmt.Errorf("could not read firmwareVersion: %w", err)
	}

	// Attested
	q := &t.Attested.Quote
	if err = binary.Read(reader, binary.BigEndian, &q.PcrSelect.Count); err != nil {
		return TPMSAttest{}, fmt.Errorf("could not read pcrSelect count: %w", err)
	}
	q.PcrSelect.PcrSelections = make([]tpmsPcrSelection, q.PcrSelect.Count)
	for i := uint32(0); i < q.PcrSelect.Count; i++ {
		newSelection := tpmsPcrSelection{}
		if err = binary.Read(reader, binary.BigEndian, &newSelection.HashAlgorithm); err != nil {
			return TPMSAttest{}, fmt.Errorf("could not read PcrSelection.hashAlgorithm: %w", err)
		}
		if err = binary.Read(reader, binary.BigEndian, &newSelection.SizeOfSelect); err != nil {
			return TPMSAttest{}, fmt.Errorf("could not read PcrSelection.sizeOfSelect: %w", err)
		}

		newSelection.PcrSelect = make(pcrSelect, newSelection.SizeOfSelect)
		if err = binary.Read(reader, binary.BigEndian, &newSelection.PcrSelect); err != nil {
			return TPMSAttest{}, fmt.Errorf("could not read PcrSelection.PcrSelect: %w", err)
		}
		q.PcrSelect.PcrSelections[i] = newSelection
	}

	if err = binary.Read(reader, binary.BigEndian, &q.PcrDigest.Size); err != nil {
		return TPMSAttest{}, fmt.Errorf("could not read PcrDigest.Size: %w", err)
	}
	q.PcrDigest.Buffer = make([]byte, q.PcrDigest.Size)
	if err = binary.Read(reader, binary.BigEndian, &q.PcrDigest.Buffer); err != nil {
		return TPMSAttest{}, fmt.Errorf("could not read PcrDigest.Buffer: %w", err)
	}

	return
}
