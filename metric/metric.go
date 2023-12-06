package metric

import (
	"fmt"
)

type Metric struct {
	Measurement string
	Name        string                 `json:"name"`
	Timestamp   int64                  `json:"timestamp"`
	Tags        map[string]string      `json:"tags"`
	Fields      map[string]interface{} `json:"fields"`
	OrgName     string                 `json:"-"`
}

func (m *Metric) AddTags(k string, v string) {
	if m.Tags == nil {
		m.Tags = make(map[string]string)
	}
	m.Tags[k] = v
}

func (m *Metric) AddField(k string, v interface{}) {
	if m.Fields == nil {
		m.Fields = make(map[string]interface{})
	}
	m.Fields[k] = v
}

func (m *Metric) String() string {
	s := fmt.Sprintf("[%s]", m.Measurement)
	for k, v := range m.Tags {
		s += fmt.Sprintf(" %s: %v", k, v)
	}
	for k, v := range m.Fields {
		s += fmt.Sprintf(" %s: %v", k, v)
	}
	s += "\n"
	return s
}
