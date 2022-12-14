package io

import (
	"bufio"
	"bytes"
	"errors"
	"github.com/uole/httpcap/internal/bufferpool"
	"io"
	"sync/atomic"
	"time"
)

var (
	ErrDeadline = errors.New("deadline")
)

type Buffer struct {
	br           *bufio.Reader
	closeFlag    int32
	closeChan    chan struct{}
	notifyChan   chan struct{}
	readDeadline time.Time
	buf          *bytes.Buffer
	lastOp       time.Time
}

func (r *Buffer) Reader() *bufio.Reader {
	return r.br
}

func (r *Buffer) Discard() {
	r.buf.Reset()
	if s := r.br.Buffered(); s > 0 {
		r.br.Discard(s)
	}
}

func (r *Buffer) PutBytes(b []byte) (err error) {
	if atomic.LoadInt32(&r.closeFlag) == 1 {
		err = io.ErrClosedPipe
		return
	}
	r.buf.Write(b)
	r.lastOp = time.Now()
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

func (r *Buffer) SetReadDeadline(t time.Time) {
	r.readDeadline = t
}

func (r *Buffer) Read(p []byte) (n int, err error) {
	var (
		tires    int
		deadline <-chan time.Time
	)
	tires = -1
	if !r.readDeadline.IsZero() {
		timer := time.NewTimer(r.readDeadline.Sub(time.Now()))
		defer timer.Stop()
		deadline = timer.C
	} else {
		deadline = make(chan time.Time)
	}
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
		case <-deadline:
			tires++
			if tires < 1 {
				goto __retry
			} else {
				err = ErrDeadline
			}
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
		bufferpool.Put(r.buf)
	}
	return
}

func NewBuffer() *Buffer {
	b := &Buffer{
		closeChan:  make(chan struct{}),
		notifyChan: make(chan struct{}, 1),
		buf:        bufferpool.Get(),
	}
	b.br = bufio.NewReader(b)
	return b
}
