package httpcap

import (
	"bytes"
	"context"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	httppkg "github.com/uole/httpcap/http"
	"net"
	"net/http"
	"sync"
)

type (
	HandleFunc func(*httppkg.Request, *httppkg.Response)

	StreamFactory struct {
		ctx        context.Context
		wg         sync.WaitGroup
		handleFunc HandleFunc
	}

	Stream struct {
		validate  bool
		in        *Buffer
		out       *Buffer
		tcp       *layers.TCP
		net       gopacket.Flow
		transport gopacket.Flow
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
	if length > 0 {
		buf = sg.Fetch(length)
		if dir == reassembly.TCPDirClientToServer {
			_ = stream.in.putBytes(buf)
		} else {
			_ = stream.out.putBytes(buf)
		}
	}
}

func (stream *Stream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	_ = stream.in.Close()
	_ = stream.out.Close()
	return true
}

func (stream *Stream) NextRequest() (req *httppkg.Request, res *httppkg.Response, err error) {
	if req, err = httppkg.ReadRequest(stream.in.Reader()); err != nil {
		return
	}
	if res, err = httppkg.ReadResponse(stream.out.Reader(), req); err != nil {
		return
	}
	return
}

func (factory *StreamFactory) process(stream *Stream) {
	defer func() {
		factory.wg.Done()
	}()
	for {
		req, res, err := stream.NextRequest()
		if err != nil {
			break
		}
		srcAddr, dstAddr := stream.net.Endpoints()
		srcPort, dstPort := stream.transport.Endpoints()
		req.Address = net.JoinHostPort(srcAddr.String(), srcPort.String())
		res.Address = net.JoinHostPort(dstAddr.String(), dstPort.String())
		if factory.handleFunc != nil {
			factory.handleFunc(req, res)
		}
	}
}

func (factory *StreamFactory) New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	stream := &Stream{
		tcp:       tcp,
		net:       netFlow,
		transport: tcpFlow,
		in:        newBuffer(nil),
		out:       newBuffer(nil),
	}
	factory.wg.Add(1)
	go factory.process(stream)
	return stream
}

func (factory *StreamFactory) Wait() {
	factory.wg.Wait()
}

func NewFactory(ctx context.Context, f HandleFunc) *StreamFactory {
	factory := &StreamFactory{
		ctx:        ctx,
		handleFunc: f,
	}
	return factory
}
