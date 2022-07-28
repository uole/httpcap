package httpcap

import "strings"

type Filter struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
	Host string `json:"host"`
	BPF  string `json:"bpf"`
}

func (filter *Filter) Match(host string) bool {
	if len(filter.Host) == 0 || filter.Host == "*" {
		return true
	}
	if pos := strings.IndexByte(host, ':'); pos > -1 {
		host = host[:pos]
	}
	if host[0] == '*' {
		return strings.HasSuffix(host, filter.Host[1:])
	}
	return host == filter.Host
}
