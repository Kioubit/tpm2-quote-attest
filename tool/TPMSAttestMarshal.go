package tool

import (
	"encoding/json"
)

func (t tpmSt) String() string {
	if t == tpmStAttestQuote {
		return "TPM_ST_ATTEST_QUOTE"
	}
	return "Unknown"
}

func (t tpmSt) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t tpmAlg) String() string {
	switch t {
	case tpmAlgSha1:
		return "TPM_ALG_SHA1"
	case tpmAlgSha256:
		return "TPM_ALG_SHA256"
	case tpmAlgSha384:
		return "TPM_ALG_SHA384"
	case tpmAlgSha512:
		return "TPM_ALG_SHA512"
	case tpmAlgSm3256:
		return "TPM_ALG_SM3_256"
	default:
		return "Unknown"
	}
}

func (t tpmAlg) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t tpmsPcrSelection) SelectedPCRs() []int {
	list := make([]int, 0)
	var pcrPos = 0
	var s uint8
	for s = 0; s < t.SizeOfSelect; s++ {
		var i uint8
		for i = 0; i < 8; i++ {
			if hasBit(t.PcrSelect[s], i) {
				list = append(list, int(i)+pcrPos)
			} else {
			}
		}
		pcrPos += 8
	}
	return list
}

func hasBit(n uint8, pos uint8) bool {
	val := n & (1 << pos)
	return val > 0
}

func (t tpmsPcrSelection) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		HashAlgorithm tpmAlg
		PcrSelect     []int
	}{
		HashAlgorithm: t.HashAlgorithm,
		PcrSelect:     t.SelectedPCRs(),
	})
}

func (t tpMiYesNo) String() string {
	if t == 1 {
		return "Yes"
	}
	return "No"
}

func (t tpMiYesNo) MarshalJSON() ([]byte, error) {
	return json.Marshal(t == 1)
}
