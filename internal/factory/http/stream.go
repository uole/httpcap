package http

import (
	"bytes"
	"fmt"
	"github.com/google/gopacket/tcpassembly"
	"github.com/uole/httpcap/internal/io"
	"net/http"
	"sync/atomic"
)

var (
	responseBytes = []byte("HTTP/")

	httpMethods = map[string]bool{
		http.MethodGet:     true,
		http.MethodPost:    true,
		http.MethodPut:     true,
		http.MethodDelete:  true,
		http.MethodHead:    true,
		http.MethodTrace:   true,
		http.MethodOptions: true,
		http.MethodPatch:   true,
	}
)

type Stream struct {
	isRequest  bool
	isResponse bool
	first      int32
	idx        int64
	buf        *io.Buffer
}

func isHttpRequest(b []byte) bool {
	var (
		pos int
	)
	if pos = bytes.IndexByte(b, ' '); pos > 0 && pos <= 8 {
		method := string(b[:pos])
		return httpMethods[method]
	}
	return false
}

func isHttpResponse(b []byte) bool {
	if len(b) > 5 {
		return bytes.Equal(b[:5], responseBytes)
	}
	return false
}

func (stream *Stream) isHttp() bool {
	return stream.isRequest || stream.isResponse
}

func (stream *Stream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	for _, reassembly := range reassemblies {
		if len(reassembly.Bytes) > 0 {
			if atomic.CompareAndSwapInt32(&stream.first, 0, 1) {
				if isHttpRequest(reassembly.Bytes) {
					stream.isRequest = true
				} else if isHttpResponse(reassembly.Bytes) {
					stream.isResponse = true
				}
			}
			if stream.isHttp() {
				fmt.Printf("stream %d put data\n", stream.idx)
				stream.buf.PutBytes(reassembly.Bytes)
			}
		}
	}
}

func (stream *Stream) ReassemblyComplete() {
	stream.buf.Close()
}
