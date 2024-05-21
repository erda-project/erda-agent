package ebpf

import (
	"net"
	"net/url"
	"strings"
)

func decodeMetrics(connTuple *ConnTuple, data *HttpPackage) (*Metric, error) {
	fragItems := strings.Split(string(data.RequestFragment[:]), "\r\n")

	metric := Metric{
		SourceIP:   net.IP(connTuple.SourceIP[:]).String(),
		SourcePort: connTuple.SourcePort,
		DestIP:     net.IP(connTuple.DestIP[:]).String(),
		DestPort:   connTuple.DestPort,
		Method:     data.Method.String(),
		Headers:    make(map[string]string),
		StatusCode: data.StatusCode,
		Duration:   data.Duration,
	}

	switch len(fragItems) {
	case 1:
		// path fragment
		parsedURL, err := url.Parse(fragItems[0])
		if err != nil {
			return nil, err
		}
		metric.Path = parsedURL.Path
	default:
		parts := strings.Split(fragItems[0], " ")
		parsedURL, err := url.Parse(parts[0])
		if err != nil {
			return nil, err
		}
		metric.Path = parsedURL.Path

		// try parse http version
		if len(parts) >= 2 {
			metric.Version = parts[1]
		}

		if len(fragItems) > 1 {
			for _, header := range fragItems[1:] {
				parts := strings.Split(header, ": ")
				if len(parts) == 2 {
					metric.Headers[parts[0]] = parts[1]
				}
				// TODO: add ... to fragment header
			}
		}
	}

	return &metric, nil
}
