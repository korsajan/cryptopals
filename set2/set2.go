package set2

import "bytes"

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
