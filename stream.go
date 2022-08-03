package httpcap

import (
	"bytes"
	"context"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	httpkg "github.com/uole/httpcap/http"
	"net"
	"net/http"
)

type (
	HandleFunc func(*httpkg.Request, *httpkg.Response)

	StreamFactory struct {
		ctx        context.Context
		handleFunc HandleFunc
	}

	Stream struct {
		validate      bool
		in            *Buffer
		out           *Buffer
		tcp           *layers.TCP
		isWebsocket   bool
		net           gopacket.Flow
		transport     gopacket.Flow
		srcAddr       string
		dstAddr       string
		numOfRequest  int32
		numOfResponse int32
	}
)

func (stream *Stream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	var (
		pos int
	)
	if !stream.validate && tcp.PSH {
		if dir == reassembly.TCPDirClientToServer && len(tcp.Payload) > 7 {
			//check http stream
			if pos = bytes.IndexByte(tcp.Payload, ' '); pos > 0 {
				method := string(tcp.Payload[:pos])
				if method == http.MethodOptions ||
					method == http.MethodDelete ||
					method == http.MethodGet ||
					method == http.MethodConnect ||
					method == http.MethodPatch ||
					method == http.MethodHead ||
					method == http.MethodPost ||
					method == http.MethodPut ||
					method == http.MethodTrace {
					stream.validate = true
				}
			}
		}
	}
	return true
}

func (stream *Stream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	var (
		buf    []byte
		dir    reassembly.TCPFlowDirection
		length int
	)
	if !stream.validate {
		return
	}
	dir, _, _, _ = sg.Info()
	length, _ = sg.Lengths()
	if length <= 0 {
		return
	}
	buf = sg.Fetch(length)
	if dir == reassembly.TCPDirClientToServer {
		_ = stream.in.putBytes(buf)
	} else {
		if stream.isWebsocket {
			return
		}
		_ = stream.out.putBytes(buf)
	}
}

func (stream *Stream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	_ = stream.in.Close()
	_ = stream.out.Close()
	return true
}

func (stream *Stream) NextRequest() (req *httpkg.Request, res *httpkg.Response, err error) {
	if req, err = httpkg.ReadRequest(stream.in.Reader()); err != nil {
		return
	}
	if req.Header.Get("Upgrade") == "websocket" {
		stream.isWebsocket = true
	}
	if res, err = httpkg.ReadResponse(stream.out.Reader(), req); err != nil {
		return
	}
	return
}

func (factory *StreamFactory) process(stream *Stream) {
	for {
		if req, res, err := stream.NextRequest(); err != nil {
			break
		} else {
			req.Address = stream.srcAddr
			res.Address = stream.dstAddr
			if factory.handleFunc != nil {
				factory.handleFunc(req, res)
			}
		}
	}
}

func (factory *StreamFactory) New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	stream := &Stream{
		tcp:       tcp,
		net:       netFlow,
		transport: tcpFlow,
		in:        newBuffer(),
		out:       newBuffer(),
	}
	srcAddr, dstAddr := stream.net.Endpoints()
	srcPort, dstPort := stream.transport.Endpoints()
	stream.srcAddr = net.JoinHostPort(srcAddr.String(), srcPort.String())
	stream.dstAddr = net.JoinHostPort(dstAddr.String(), dstPort.String())
	go factory.process(stream)
	return stream
}

func NewFactory(ctx context.Context, f HandleFunc) *StreamFactory {
	factory := &StreamFactory{
		ctx:        ctx,
		handleFunc: f,
	}
	return factory
}
