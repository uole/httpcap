package tcp

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	httpkg "github.com/uole/httpcap/http"
	iopkg "github.com/uole/httpcap/internal/io"
	"io"
	"net/http"
	"sync/atomic"
	"time"
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

type (
	Stream struct {
		id          int64
		up          *iopkg.Buffer
		down        *iopkg.Buffer
		tcp         *layers.TCP
		net         gopacket.Flow
		transport   gopacket.Flow
		srcAddr     string
		dstAddr     string
		isHttp      bool
		isWebsocket bool
		abnormal    int32
		writer      io.Writer
	}
)

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

func (stream *Stream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	if !stream.isHttp && tcp.PSH {
		if len(tcp.Payload) > 8 {
			stream.isHttp = isHttpRequest(tcp.Payload)
		}
	}
	return true
}

func (stream *Stream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	var (
		buf    []byte
		length int
		dir    reassembly.TCPFlowDirection
	)
	dir, _, _, _ = sg.Info()
	length, _ = sg.Lengths()
	if stream.isHttp && length > 0 {
		buf = sg.Fetch(length)
		if atomic.LoadInt32(&stream.abnormal) == 1 {
			if isHttpRequest(buf) {
				stream.Discard()
				atomic.StoreInt32(&stream.abnormal, 0)
			}
		}
		if dir == reassembly.TCPDirClientToServer {
			_ = stream.up.PutBytes(buf)
		} else {
			_ = stream.down.PutBytes(buf)
		}
	}
}

func (stream *Stream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	_ = stream.up.Close()
	_ = stream.down.Close()
	return true
}

func (stream *Stream) Discard() {
	stream.up.Discard()
	stream.down.Discard()
}

func (stream *Stream) Close() {
	_ = stream.up.Close()
	_ = stream.down.Close()
}

func (stream *Stream) FetchRequest() (req *httpkg.Request, res *httpkg.Response, err error) {
__retry:
	if req, err = httpkg.ReadRequest(stream.up.Reader()); err != nil {
		if stream.writer != nil {
			fmt.Fprintf(stream.writer, "stream %d read request error: %s\n", stream.id, err.Error())
		}
		if !errors.Is(err, io.ErrClosedPipe) {
			atomic.StoreInt32(&stream.abnormal, 1)
			stream.Discard()
			goto __retry
		}
		return
	}
	if !stream.isWebsocket {
		if req.Header.Get("Upgrade") == "websocket" {
			stream.isWebsocket = true
		}
	}
	stream.down.SetReadDeadline(time.Now().Add(time.Second * 10))
	if res, err = httpkg.ReadResponse(stream.down.Reader(), req); err != nil {
		if stream.writer != nil {
			fmt.Fprintf(stream.writer, "stream %d read response error: %s\n", stream.id, err.Error())
		}
		if !errors.Is(err, io.ErrClosedPipe) {
			atomic.StoreInt32(&stream.abnormal, 1)
			stream.Discard()
			goto __retry
		}
	}
	return
}
