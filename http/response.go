package http

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/valyala/bytebufferpool"
	"io"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"strconv"
	"strings"
)

type Response struct {
	Request       *Request
	Status        string
	StatusCode    int
	Proto         string
	Header        http.Header
	Body          []byte
	ContentLength int
	Address       string
}

func (r *Response) WriteTo(w io.Writer) (n int64, err error) {
	writer := bytebufferpool.Get()
	defer bytebufferpool.Put(writer)
	_, err = writer.WriteString(r.Proto + " " + strconv.Itoa(r.StatusCode) + " " + r.Status)
	_, err = writer.WriteString("\r\n")
	err = r.Header.Write(writer)
	_, err = writer.WriteString("\r\n")
	if r.ContentLength > 0 {
		_, err = writer.Write(r.Body)
	}
	return writer.WriteTo(w)
}

func ReadResponse(r *bufio.Reader, req *Request) (res *Response, err error) {
	var (
		line       string
		mimeHeader textproto.MIMEHeader
	)
	tp := newTextprotoReader(r)
	res = &Response{
		Request: req,
	}
	defer func() {
		putTextprotoReader(tp)
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()
	// Parse the first line of the response.
	if line, err = tp.ReadLine(); err != nil {
		return
	}
	if i := strings.IndexByte(line, ' '); i == -1 {
		return nil, fmt.Errorf("malformed HTTP response %s", line)
	} else {
		res.Proto = line[:i]
		res.Status = strings.TrimLeft(line[i+1:], " ")
	}
	statusCode := res.Status
	if i := strings.IndexByte(res.Status, ' '); i != -1 {
		statusCode = res.Status[:i]
	}
	if len(statusCode) != 3 {
		return nil, fmt.Errorf("malformed HTTP status code %s", statusCode)
	}
	if res.StatusCode, err = strconv.Atoi(statusCode); err != nil || res.StatusCode < 0 {
		return nil, fmt.Errorf("malformed HTTP status code %s", statusCode)
	}
	// Parse the response headers.
	if mimeHeader, err = tp.ReadMIMEHeader(); err != nil {
		return
	}
	res.Header = http.Header(mimeHeader)
	if strings.EqualFold(res.Header.Get("Transfer-Encoding"), "chunked") {
		reader := httputil.NewChunkedReader(r)
		if res.Body, err = io.ReadAll(reader); err == nil {
			res.ContentLength = len(res.Body)
		}
	} else if res.Header.Get("Content-Length") != "" {
		res.ContentLength, _ = strconv.Atoi(res.Header.Get("Content-Length"))
		if res.ContentLength > 0 {
			res.Body = make([]byte, res.ContentLength)
			_, err = io.ReadFull(r, res.Body)
		}
	} else {
		if res.Body, err = io.ReadAll(r); err != nil {
			if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.EOF) {
				err = nil
			}
		}
		res.ContentLength = len(res.Body)
	}
	return
}
