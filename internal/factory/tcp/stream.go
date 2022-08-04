package tcp

import (
	"bytes"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	httpkg "github.com/uole/httpcap/http"
	iopkg "github.com/uole/httpcap/internal/io"
	"io"
	"net/http"
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
		if dir == reassembly.TCPDirClientToServer {
			if stream.up.Abnormal() {
				if isHttpRequest(buf) {
					stream.up.Discard()
				}
			}
			_ = stream.up.PutBytes(buf)
		} else {
			if stream.down.Abnormal() {
				if isHttpResponse(buf) {
					stream.down.Discard()
				}
			}
			_ = stream.down.PutBytes(buf)
		}
	}
}

func (stream *Stream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	_ = stream.up.Close()
	_ = stream.down.Close()
	return true
}

func (stream *Stream) FetchRequest() (req *httpkg.Request, res *httpkg.Response, err error) {
__retry:
	if req, err = httpkg.ReadRequest(stream.up.Reader()); err != nil {
		if !errors.Is(err, io.ErrClosedPipe) {
			stream.up.SetAbnormal()
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
		if !errors.Is(err, io.ErrClosedPipe) {
			stream.down.SetAbnormal()
			goto __retry
		}
	}
	return
}
