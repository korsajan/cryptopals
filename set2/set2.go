package set2

import (
	"bytes"
	"crypto/cipher"
)

func paddingPKCS7(b []byte, size int) []byte {
	paddingLen := size - (len(b) % size)

	buf := bytes.Buffer{}
	buf.Grow(len(b) + paddingLen)
	buf.Write(b)

	c := byte(paddingLen)
	for i := len(b); i < len(b)+paddingLen; i++ {
		buf.WriteByte(c)
	}

	return buf.Bytes()
}

func encryptedCBC(plaintText []byte, block cipher.Block, iv []byte) []byte {
	if len(plaintText)%block.BlockSize() != 0 {
		panic("invalid input length")
	}
	if len(iv) != block.BlockSize() {
		panic("invalid iv length")
	}

	cipherText := make([]byte, len(plaintText))
	prev := iv
	bs := block.BlockSize()
	n := len(plaintText) / bs
	for i := 0; i < n; i++ {
		block.Encrypt(cipherText[i*bs:(i+1)*bs], xorBytes(plaintText[:bs], prev))
		prev = cipherText[i*bs : (i+1)*bs]
		plaintText = plaintText[bs:]
	}

	return cipherText
}

func decryptedCBC(cipherText []byte, block cipher.Block, iv []byte) []byte {
	if len(cipherText)%block.BlockSize() != 0 {
		panic("invalid input length")
	}
	if len(iv) != block.BlockSize() {
		panic("invalid iv length")
	}

	plainText := make([]byte, len(cipherText))
	bs := block.BlockSize()
	n := len(cipherText) / bs
	prev := iv
	for i := 0; i < n; i++ {
		block.Decrypt(plainText[i*bs:(i+1)*bs], cipherText[i*bs:])
		copy(plainText[i*bs:(i+1)*bs], xorBytes(plainText[i*bs:(i+1)*bs], prev))
		prev = cipherText[i*bs : (i+1)*bs]
	}
	return plainText
}

func xorBytes(a, b []byte) []byte {
	if len(a) > len(b) {
		a = a[:len(b)]
	}
	var out = make([]byte, len(a))
	for i := 0; i < len(out); i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}
