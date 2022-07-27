package httpcap

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"sync/atomic"
	"time"
)

type Buffer struct {
	br         *bufio.Reader
	closeFlag  int32
	closeChan  chan struct{}
	notifyChan chan struct{}
	buf        *bytes.Buffer
}

func (r *Buffer) Reader() *bufio.Reader {
	return r.br
}

func (r *Buffer) putBytes(b []byte) (err error) {
	if atomic.LoadInt32(&r.closeFlag) == 1 {
		err = io.ErrClosedPipe
		return
	}
	r.buf.Write(b)
	select {
	case r.notifyChan <- struct{}{}:
	case <-r.closeChan:
		err = io.ErrClosedPipe
	case <-time.After(time.Millisecond * 100):
	}
	return
}

func (r *Buffer) Reset() {
	r.buf.Reset()
	r.closeFlag = 0
	r.closeChan = make(chan struct{})
	r.notifyChan = make(chan struct{}, 1)
}

func (r *Buffer) Read(p []byte) (n int, err error) {
__retry:
	if atomic.LoadInt32(&r.closeFlag) == 1 {
		if r.buf.Len() > 0 {
			return r.buf.Read(p)
		}
		err = io.ErrClosedPipe
		return
	}
	if n, err = r.buf.Read(p); err == nil {
		return
	}
	if errors.Is(err, io.EOF) {
		select {
		case <-r.closeChan:
			err = io.ErrClosedPipe
		case <-r.notifyChan:
			goto __retry
		}
	}
	return
}

func (r *Buffer) Close() (err error) {
	if atomic.CompareAndSwapInt32(&r.closeFlag, 0, 1) {
		close(r.closeChan)
		close(r.notifyChan)
	}
	return
}

func newBuffer(buf *bytes.Buffer) *Buffer {
	if buf == nil {
		buf = new(bytes.Buffer)
	}
	b := &Buffer{
		closeChan:  make(chan struct{}),
		notifyChan: make(chan struct{}, 1),
		buf:        buf,
	}
	b.br = bufio.NewReader(b)
	return b
}
