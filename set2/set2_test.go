package set2

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"io/ioutil"
	"testing"
)

func TestSet2Challenge9(t *testing.T) {
	in := []byte("YELLOW SUBMARINE")
	out := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	res := paddingPKCS7(in, 20)
	if !bytes.Equal(res, out) {
		t.Fatalf("wrongs res ex: %s got: %s\n", out, res)
	}
}

func TestSet2Challenge10(t *testing.T) {
	plaintText := []byte("YELLOW SUBMARINEYELLOW SUBMARINE")
	iv := make([]byte, 16)
	b, _ := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	res := decryptedCBC(encryptedCBC(plaintText, b, iv), b, iv)
	if !bytes.Equal(plaintText, res) {
		t.Errorf("invalid result %s\n", string(res))
	}

	data := decodeBase64(t, string(readFile(t, "./challengedata/challenge10.txt")))
	t.Logf("decrypted res:\n%s", decryptedCBC(data, b, iv))
}

func TestSet2Challenge11(t *testing.T) {
	b := bytes.Repeat([]byte{1}, 3*16)
	ecb, cbc := 0, 0
	for i := 0; i < 100; i++ {
		out := newOracle()(b)
		if ecbDetected(out) {
			ecb++
		} else {
			cbc++
		}
	}

	t.Logf("ecb : %d cbc : %d\n", ecb, cbc)
}

func decodeBase64(t *testing.T, s string) []byte {
	t.Helper()
	v, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode base64: %s\n", s)
	}
	return v
}

func readFile(t *testing.T, filename string) []byte {
	t.Helper()
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed open file %s with err %s\n", filename, err.Error())
	}
	return data
}
