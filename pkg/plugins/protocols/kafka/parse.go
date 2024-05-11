package kafka

import "encoding/binary"

type Event struct {
	ConnTuple
	Transaction
}

type ConnTuple struct {
	DestIP     [4]byte
	DestPort   uint32
	SourceIP   [4]byte
	SourcePort uint32
}

type Transaction struct {
	RequestStarted    uint64
	RecordCount       uint32
	RequestApiKey     uint8
	RequestApiVersion uint8
	TopicNameSize     uint8
	TopicName         string
}

type ResponseContext struct {
	State                 int8
	Remainder             uint8
	RemainderBuf          string
	RecordBatchesNumBytes uint32
	RecordBatchLength     uint32
	ExpectedTcpSeq        uint32
	CarryOverOffset       uint32
	PartitionCount        uint32
	Transaction
}

func decodeResponse(data []byte) Transaction {
	ans := Transaction{}
	ans.RequestStarted = binary.LittleEndian.Uint64(data[0:8])
	ans.RecordCount = binary.LittleEndian.Uint32(data[8:12])
	ans.RequestApiKey = data[12]
	ans.RequestApiVersion = data[13]
	ans.TopicNameSize = data[14]
	topicEnd := len(data)
	if 15+int(ans.TopicNameSize) < topicEnd {
		topicEnd = 15 + int(ans.TopicNameSize)
	}
	ans.TopicName = string(data[15:topicEnd])
	return ans
}
