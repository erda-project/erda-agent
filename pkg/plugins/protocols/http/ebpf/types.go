package ebpf

import (
	"fmt"
	"net/http"
	"time"
)

const (
	HttpPayloadSize = 224
)

type HttpMethod uint8

const (
	HTTP_METHOD_UNKNOWN HttpMethod = iota
	HttpGet
	HttpPost
	HttpPut
	HttpDelete
	HttpHead
	HttpOptions
	HttpPatch
)

var httpMethodMap = map[HttpMethod]string{
	HttpGet:     http.MethodGet,
	HttpPost:    http.MethodPost,
	HttpPut:     http.MethodPut,
	HttpDelete:  http.MethodDelete,
	HttpHead:    http.MethodHead,
	HttpOptions: http.MethodOptions,
	HttpPatch:   http.MethodPatch,
}

func (m HttpMethod) String() string {
	if method, ok := httpMethodMap[m]; ok {
		return method
	}
	return m.Unknown()
}

func (m HttpMethod) Unknown() string {
	return "Unknown HttpMethod"
}

type HttpPackage struct {
	RequestTimestamp uint64
	Duration         uint64
	StatusCode       uint16
	Method           HttpMethod
	RequestFragment  [HttpPayloadSize]byte
}

type ConnTuple struct {
	SourceIP   [4]byte
	DestIP     [4]byte
	SourcePort uint16
	DestPort   uint16
}

type Metric struct {
	SourceIP   string
	SourcePort uint16
	DestIP     string
	DestPort   uint16
	Method     string
	Path       string
	Version    string
	Headers    map[string]string
	StatusCode uint16
	Duration   uint64
}

func (m *Metric) String() string {
	return fmt.Sprintf("%s http [%s:%d] --> [%s:%d][%s %s %s] ====> %d [%s] \n%+v\n",
		time.Now().Format("2006-01-02 15:04:05"),
		m.SourceIP, m.SourcePort, m.DestIP, m.DestPort, m.Method, m.Path, m.Version, m.StatusCode,
		time.Duration(m.Duration).String(), m.Headers,
	)
}
