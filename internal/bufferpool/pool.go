package bufferpool

import (
	"bytes"
	"sync"
)

var (
	bufferPool sync.Pool
)

func Get() *bytes.Buffer {
	if v := bufferPool.Get(); v != nil {
		return v.(*bytes.Buffer)
	}
	return bytes.NewBuffer([]byte{})
}

func Put(b *bytes.Buffer) {
	b.Reset()
	bufferPool.Put(b)
}
