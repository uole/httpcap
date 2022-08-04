package factory

import httpkg "github.com/uole/httpcap/http"

type (
	HandleFunc func(*httpkg.Request, *httpkg.Response)
)
