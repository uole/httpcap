package tcp

import (
	"context"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/uole/httpcap/internal/factory"
	iopkg "github.com/uole/httpcap/internal/io"
	"net"
	"os"
	"path"
	"sync/atomic"
)

type Factory struct {
	ctx        context.Context
	idx        int64
	handleFunc factory.HandleFunc
	fp         *os.File
}

func (factory *Factory) process(stream *Stream) {
	for {
		if req, res, err := stream.FetchRequest(); err != nil {
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

func (factory *Factory) New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	stream := &Stream{
		id:        atomic.AddInt64(&factory.idx, 1),
		tcp:       tcp,
		writer:    factory.fp,
		net:       netFlow,
		transport: tcpFlow,
		up:        iopkg.NewBuffer(),
		down:      iopkg.NewBuffer(),
	}
	stream.srcAddr = net.JoinHostPort(netFlow.Src().String(), tcp.SrcPort.String())
	stream.dstAddr = net.JoinHostPort(netFlow.Dst().String(), tcp.DstPort.String())
	go factory.process(stream)
	return stream
}

func New(ctx context.Context, cb factory.HandleFunc) *Factory {
	f := &Factory{
		ctx:        ctx,
		handleFunc: cb,
	}
	f.fp, _ = os.OpenFile(path.Join(os.TempDir(), "httpcap"), os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	return f
}
