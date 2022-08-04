package http

import (
	"context"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/uole/httpcap/internal/factory"
	"github.com/uole/httpcap/internal/io"
	"sync/atomic"
)

type Factory struct {
	sequence   int64
	ctx        context.Context
	handleFunc factory.HandleFunc
}

func (f *Factory) process(stream *Stream) {

}

func (f *Factory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	stream := &Stream{
		buf: io.NewBuffer(),
		idx: atomic.AddInt64(&f.sequence, 1),
	}
	go f.process(stream)
	return stream
}

func New(ctx context.Context, cb factory.HandleFunc) *Factory {
	f := &Factory{
		ctx:        ctx,
		handleFunc: cb,
	}
	return f
}
