package tcp

import (
	"context"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/uole/httpcap/internal/factory"
	iopkg "github.com/uole/httpcap/internal/io"
	"net"
	"os"
	"path"
	"sync"
	"sync/atomic"
)

type Factory struct {
	ctx         context.Context
	idx         int64
	handleFunc  factory.HandleFunc
	writeCloser *os.File
	mutex       sync.RWMutex
	streams     map[int64]*Stream
}

func (factory *Factory) process(stream *Stream) {
	for {
		if req, res, err := stream.FetchRequest(); err != nil {
			_, _ = factory.writeCloser.WriteString(fmt.Sprintf("stream %d fetch request error: %s\n", stream.id, err.Error()))
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
		writer:    factory.writeCloser,
		net:       netFlow,
		transport: tcpFlow,
		up:        iopkg.NewBuffer(),
		down:      iopkg.NewBuffer(),
	}
	stream.srcAddr = net.JoinHostPort(netFlow.Src().String(), tcp.SrcPort.String())
	stream.dstAddr = net.JoinHostPort(netFlow.Dst().String(), tcp.DstPort.String())
	//factory.mutex.Lock()
	//factory.streams[stream.id] = stream
	//factory.mutex.Unlock()
	go factory.process(stream)
	return stream
}

func (factory *Factory) Close() (err error) {
	err = factory.writeCloser.Close()
	return
}

func New(ctx context.Context, cb factory.HandleFunc) *Factory {
	f := &Factory{
		ctx:        ctx,
		handleFunc: cb,
		streams:    make(map[int64]*Stream),
	}
	f.writeCloser, _ = os.OpenFile(path.Join(os.TempDir(), "httpcap"), os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	return f
}
