package http

import (
	"bufio"
	"fmt"
	"github.com/uole/httpcap/internal/bytepool"
	"github.com/valyala/bytebufferpool"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
)

type Request struct {
	Proto         string
	RequestURI    string
	Method        string
	Host          string
	Header        http.Header
	ContentLength int
	Body          []byte
	Address       string
}

func (r *Request) Release() {
	if r.ContentLength > 0 {
		bytepool.Put(r.Body)
	}
}

func (r *Request) WriteTo(w io.Writer) (n int64, err error) {
	writer := bytebufferpool.Get()
	defer bytebufferpool.Put(writer)
	_, err = writer.WriteString(r.Method + " " + r.RequestURI + " " + r.Proto)
	_, err = writer.WriteString("\r\n")
	err = r.Header.Write(writer)
	_, err = writer.WriteString("\r\n")
	if r.ContentLength > 0 {
		_, err = writer.Write(r.Body)
	}
	return writer.WriteTo(w)
}

func ReadRequest(b *bufio.Reader) (req *Request, err error) {
	var (
		ok         bool
		s          string
		mimeHeader textproto.MIMEHeader
	)
	tp := newTextprotoReader(b)
	req = new(Request)
	for {
		if s, err = tp.ReadLine(); err != nil {
			return nil, err
		}
		if len(s) > 0 {
			break
		}
	}
	defer func() {
		putTextprotoReader(tp)
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()
	if req.Method, req.RequestURI, req.Proto, ok = parseRequestLine(s); !ok {
		err = fmt.Errorf("malformed HTTP request %s", s)
		return
	}
	if mimeHeader, err = tp.ReadMIMEHeader(); err != nil {
		return
	}
	req.Header = http.Header(mimeHeader)
	if len(req.Header["Host"]) > 1 {
		err = fmt.Errorf("too many Host headers")
		return
	}
	req.Host = req.Header.Get("Host")
	req.ContentLength, _ = strconv.Atoi(req.Header.Get("Content-Length"))
	if req.ContentLength > 0 {
		req.Body = bytepool.Get(req.ContentLength)
		_, err = io.ReadFull(b, req.Body)
	}
	return
}
