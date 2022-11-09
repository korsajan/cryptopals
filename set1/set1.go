package set1

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"strings"
	"unicode/utf8"
)

// challenge 1
func hexToBase64(str string) (string, error) {
	b, err := hex.DecodeString(str)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// challenge 2
func fixedXOR(s1, s2 string) (string, error) {
	b1 := mustDecodeHex(s1)
	b2 := mustDecodeHex(s2)

	// output to b1
	b, err := xor(b1, b2)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

func xor(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("length not equal")
	}
	var out = make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		out[i] = a[i] ^ b[i]
	}
	return out, nil
}

func xorSingle(a []byte, b byte) []byte {
	var out = make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		out[i] = a[i] ^ b
	}
	return out
}

func score(s string, freqMap map[rune]float64) float64 {
	var result float64
	for i := 0; i < len(s); i++ {
		r := rune(s[i])
		result += freqMap[r]
	}

	return result
}

func freqSymbol(r io.Reader) (map[rune]float64, error) {
	freq := make(map[rune]float64)
	var sb strings.Builder
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		sb.Write(scanner.Bytes())
	}
	err := scanner.Err()
	if err != nil {
		log.Fatal(err)
	}
	totalCount := utf8.RuneCountInString(sb.String())

	for _, s := range sb.String() {
		freq[s]++
	}
	for s := range freq {
		freq[s] = (freq[s] * 100) / float64(totalCount)
	}
	return freq, nil
}

func searchSingleXor(b []byte, freqMap map[rune]float64) ([]byte, byte, float64) {
	var res []byte
	var k byte
	var total float64
	for i := 0; i < 256; i++ {
		out := xorSingle(b, byte(i))
		s := score(string(out), freqMap)
		if s > total {
			total = s
			res = out
			k = byte(i)
		}
	}
	return res, k, total
}

func repeatedXor(text []byte, key []byte) []byte {
	out := make([]byte, len(text))
	for i := 0; i < len(text); i++ {
		out[i] = text[i] ^ key[i%len(key)]
	}
	return out
}

func mustDecodeHex(text string) []byte {
	b, err := hex.DecodeString(text)
	if err != nil {
		panic(err)
	}
	return b
}