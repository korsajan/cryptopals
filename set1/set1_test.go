package set1

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
)

func TestSet1Challenge1(t *testing.T) {
	in := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	out := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	res, err := hexToBase64(in)
	if err != nil {
		t.Fatal(err)
	}

	if out != res {
		t.Fatalf("test failed ex : %s got : %s\n", out, res)
	}
}

func TestSet1Challenge2(t *testing.T) {
	s1 := "1c0111001f010100061a024b53535009181c"
	s2 := "686974207468652062756c6c277320657965"
	out := "746865206b696420646f6e277420706c6179"

	if res, err := fixedXOR(s1, s2); res != out {
		if err != nil {
			t.Fatal(err)
		}
		t.Fatalf("test failed ex: %s got : %s\n", out, res)
	}
}

func TestSet1Challenge3(t *testing.T) {
	in := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	b, err := hex.DecodeString(in)
	if err != nil {
		t.Fatal(err)
	}

	for i := 1; i <= 256; i++ {
		_ = xorSingle(b, byte(i))
	}
	// found key = 'X'
	fmt.Println(string(xorSingle(b, 'X')))
}

var corpup = mustBuildCorpus()

func TestSet1Challenge4(t *testing.T) {
	data, err := ioutil.ReadFile("./challengedata/challenge4.txt")
	if err != nil {
		t.Error(err)
	}

	bestScore := float64(0)
	var res []byte
	var scanner = bufio.NewScanner(bytes.NewReader(data))
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		candidate, _, s := searchSingleXor(mustDecodeHex(scanner.Text()), corpup)
		if s > bestScore {
			bestScore = s
			res = candidate
		}
	}

	t.Logf("res: \"%s\" :: score %.2f \n", strings.TrimSpace(string(res)), bestScore)
}

func TestSet1Challenge5(t *testing.T) {
	plainText := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	cipherText := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	res := repeatedXor([]byte(plainText), []byte("ICE"))
	if !bytes.Equal(mustDecodeHex(cipherText), res) {
		t.Errorf("wrong result %s\n", res)
	}
}

func TestSet1Challenge6(t *testing.T) {
	data, err := ioutil.ReadFile("./challengedata/challenge5.txt")
	if err != nil {
		t.Error(err)
	}
	cipherText := mustBase64ToBinary(string(data))
	keySize := searchKeySize(cipherText)

	var buf, key bytes.Buffer
	for i := 0; i < keySize; i++ {
		// padding buffer get 0 29 0 58  1 30 1 59 etc
		for j := 0; j < keySize; j++ {
			buf.WriteByte(cipherText[j*keySize+i])
		}
		c := searchSingleXorKey(buf.Bytes(), corpup)
		key.WriteByte(c)
		buf.Reset()
	}
	t.Logf("key is \"%s\"\n", key.String())
}
