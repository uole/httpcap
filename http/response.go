package http

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/uole/httpcap/internal/bytepool"
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
	_isBinary     int
}

func (r *Response) isBinary() bool {
	var (
		numOfText int
	)
	if r._isBinary == 1 {
		return true
	}
	if r._isBinary == -1 {
		return false
	}
	length := r.ContentLength
	if length > 100 {
		length = 100
	}
	for i := 0; i < length; i++ {
		if r.Body[i] <= 6 || (r.Body[i] >= 14 && r.Body[i] <= 31) {
			r._isBinary = 1
			break
		}
		if r.Body[i] >= 0x20 || r.Body[i] == 9 || r.Body[i] == 10 || r.Body[i] == 13 {
			numOfText++
		}
	}
	if r._isBinary == 0 {
		if numOfText > length/2 {
			r._isBinary = -1
		} else {
			r._isBinary = 1
		}
	}
	return r.isBinary()
}

func (r *Response) Release() {
	if r.ContentLength > 0 {
		bytepool.Put(r.Body)
	}
}

func (r *Response) WriteTo(w io.Writer) (n int64, err error) {
	writer := bytebufferpool.Get()
	defer bytebufferpool.Put(writer)
	_, err = writer.WriteString(r.Proto + " " + strconv.Itoa(r.StatusCode) + " " + r.Status)
	_, err = writer.WriteString("\r\n")
	err = r.Header.Write(writer)
	_, err = writer.WriteString("\r\n")
	if r.ContentLength > 0 {
		if !r.isBinary() {
			_, err = writer.Write(r.Body)
		} else {
			wc := hex.Dumper(writer)
			wc.Write(r.Body)
			wc.Close()
		}
	}
	return writer.WriteTo(w)
}

func (r *Response) Dumper(w io.Writer, displayLargeBody bool) (n int64, err error) {
	writer := bytebufferpool.Get()
	defer bytebufferpool.Put(writer)
	_, err = writer.WriteString(r.Proto + " " + strconv.Itoa(r.StatusCode) + " " + r.Status)
	_, err = writer.WriteString("\r\n")
	err = r.Header.Write(writer)
	_, err = writer.WriteString("\r\n")
	if r.ContentLength > 0 {
		if r.ContentLength < 1024 || displayLargeBody {
			if !r.isBinary() {
				_, err = writer.Write(r.Body)
			} else {
				wc := hex.Dumper(writer)
				wc.Write(r.Body)
				wc.Close()
			}
		}
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
	for {
		if line, err = tp.ReadLine(); err != nil {
			return
		}
		if len(line) > 0 {
			break
		}
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
		res.Status = res.Status[i+1:]
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
		reader := httputil.NewChunkedReader(tp.R)
		if res.Body, err = io.ReadAll(reader); err == nil {
			res.ContentLength = len(res.Body)
		}
	} else if res.Header.Get("Content-Length") != "" {
		res.ContentLength, _ = strconv.Atoi(res.Header.Get("Content-Length"))
		if res.ContentLength > 0 {
			res.Body = bytepool.Get(res.ContentLength)
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
