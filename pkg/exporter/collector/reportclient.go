package collector

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/erda-project/ebpf-agent/metric"
)

type config struct {
	ReportConfig ReportConfig `file:"report_config"`
}

type CollectorConfig struct {
	Addr     string `file:"addr" env:"COLLECTOR_ADDR" default:"collector:7076"`
	UserName string `file:"username" env:"COLLECTOR_AUTH_USERNAME"`
	Password string `file:"password" env:"COLLECTOR_AUTH_PASSWORD"`
	Retry    int    `file:"retry" env:"TELEMETRY_REPORT_STRICT_RETRY" default:"3"`
}

type ReportConfig struct {
	UdpHost string `file:"udp_host" env:"HOST_IP" default:"localhost"`
	UdpPort string `file:"upd_port" env:"HOST_PORT" default:"7082"`

	Collector CollectorConfig `file:"collector"`

	BufferSize int `file:"buffer_size" env:"REPORT_BUFFER_SIZE" default:"200"`
}

type ReportClient struct {
	CFG        *config
	HttpClient *http.Client
}

type NamedMetrics struct {
	Name    string
	Metrics Metrics `json:"metrics"`
}

type Metrics []*metric.Metric

func (c *ReportClient) SetCFG(cfg *config) {
	c.CFG = cfg
}

func CreateReportClient(cfg *CollectorConfig) *ReportClient {
	return &ReportClient{
		CFG: &config{
			ReportConfig: ReportConfig{
				Collector: CollectorConfig{
					Addr:     cfg.Addr,
					UserName: cfg.UserName,
					Password: cfg.Password,
					Retry:    cfg.Retry,
				},
			},
		}, HttpClient: new(http.Client),
	}
}

func (c *ReportClient) Send(in []*metric.Metric) error {
	groups := c.group(in)
	for _, group := range groups {
		if len(group.Metrics) == 0 {
			continue
		}
		requestBuffer, err := c.serialize(group)
		if err != nil {
			continue
		}
		for i := 0; i < c.CFG.ReportConfig.Collector.Retry; i++ {
			if err = c.write(group.Name, requestBuffer); err == nil {
				break
			}
			fmt.Printf("%s E! Retry %d # report in to collector error %s \n", time.Now().Format("2006-01-02 15:04:05"), i, err.Error())
		}
	}
	return nil
}

func (c *ReportClient) serialize(group *NamedMetrics) (io.Reader, error) {
	requestContent, err := json.Marshal(map[string]interface{}{group.Name: group.Metrics})
	if err != nil {
		return nil, err
	}
	base64Content := make([]byte, base64.StdEncoding.EncodedLen(len(requestContent)))
	base64.StdEncoding.Encode(base64Content, requestContent)
	return CompressWithGzip(bytes.NewBuffer(base64Content))
}

func (c *ReportClient) group(in []*metric.Metric) []*NamedMetrics {
	metrics := &NamedMetrics{
		Name:    "metrics",
		Metrics: make([]*metric.Metric, 0),
	}
	trace := &NamedMetrics{
		Name:    "trace",
		Metrics: make([]*metric.Metric, 0),
	}
	errorG := &NamedMetrics{
		Name:    "error",
		Metrics: make([]*metric.Metric, 0),
	}
	for _, m := range in {
		switch m.Name {
		case "trace":
		case "span":
			trace.Metrics = append(trace.Metrics, m)
			break
		case "error":
			errorG.Metrics = append(errorG.Metrics, m)
			break
		default:
			metrics.Metrics = append(metrics.Metrics, m)
		}
	}
	return []*NamedMetrics{metrics, trace, errorG}
}

func (c *ReportClient) write(name string, requestBuffer io.Reader) error {
	req, err := http.NewRequest(http.MethodPost, c.formatRoute(name), requestBuffer)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Custom-Content-Encoding", "base64")
	req.Header.Set("Content-Type", "application/json")
	if len(c.CFG.ReportConfig.Collector.UserName) > 0 {
		req.SetBasicAuth(c.CFG.ReportConfig.Collector.UserName, c.CFG.ReportConfig.Collector.Password)
	}
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err = fmt.Errorf("when writing to [%s] received status code: %d\n", c.formatRoute(name), resp.StatusCode)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("%s error! close response body error %s\n", time.Now().Format("2006-01-02 15:04:05"), err)
		}
	}()
	return err
}

func (c *ReportClient) formatRoute(name string) string {
	addr := c.CFG.ReportConfig.Collector.Addr
	if !strings.HasPrefix(addr, "https://") && !strings.HasPrefix(addr, "http://") {
		addr = "https://" + addr
	}
	return fmt.Sprintf("%s/collect/%s", addr, name)
}

func CompressWithGzip(data io.Reader) (io.Reader, error) {
	pipeReader, pipeWriter := io.Pipe()
	gzipWriter := gzip.NewWriter(pipeWriter)

	var err error
	go func() {
		_, err = io.Copy(gzipWriter, data)
		gzipWriter.Close()
		// subsequent reads from the read half of the pipe will
		// return no bytes and the error err, or EOF if err is nil.
		pipeWriter.CloseWithError(err)
	}()

	return pipeReader, err
}
