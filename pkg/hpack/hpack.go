package hpack

import (
	"errors"
	"fmt"
	"math"
)

var staticTable = [][2]string{
	{":authority", ""},
	{":method", "GET"},
	{":method", "POST"},
	{":path", "/"},
	{":path", "/index.html"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "200"},
	{":status", "204"},
	{":status", "206"},
	{":status", "304"},
	{":status", "400"},
	{":status", "404"},
	{":status", "500"},
	{"accept-charset", ""},
	{"accept-encoding", "gzip, deflate"},
	{"accept-language", ""},
	{"accept-ranges", ""},
	{"accept", ""},
	{"access-control-allow-origin", ""},
	{"age", ""},
	{"allow", ""},
	{"authorization", ""},
	{"cache-control", ""},
	{"content-disposition", ""},
	{"content-encoding", ""},
	{"content-language", ""},
	{"content-length", ""},
	{"content-location", ""},
	{"content-range", ""},
	{"content-type", ""},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"expect", ""},
	{"expires", ""},
	{"from", ""},
	{"host", ""},
	{"if-match", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"if-range", ""},
	{"if-unmodified-since", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"max-forwards", ""},
	{"proxy-authenticate", ""},
	{"proxy-authorization", ""},
	{"range", ""},
	{"referer", ""},
	{"refresh", ""},
	{"retry-after", ""},
	{"server", ""},
	{"set-cookie", ""},
	{"strict-transport-security", ""},
	{"transfer-encoding", ""},
	{"user-agent", ""},
	{"vary", ""},
	{"via", ""},
	{"www-authenticate", ""},
}

var staticTableEncoding = map[string]int{
	":authority":                  1,
	":method":                     2,
	":path":                       4,
	":scheme":                     6,
	":status":                     8,
	"accept-encoding":             16,
	"accept-charset":              15,
	"accept-language":             17,
	"accept-ranges":               18,
	"accept":                      19,
	"access-control-allow-origin": 20,
	"age":                         21,
	"allow":                       22,
	"authorization":               23,
	"cache-control":               24,
	"content-disposition":         25,
	"content-encoding":            26,
	"content-language":            27,
	"content-length":              28,
	"content-location":            29,
	"content-range":               30,
	"content-type":                31,
	"cookie":                      32,
	"date":                        33,
	"etag":                        34,
	"expect":                      35,
	"expires":                     36,
	"from":                        37,
	"host":                        38,
	"if-match":                    39,
	"if-modified-since":           40,
	"if-none-match":               41,
	"if-range":                    42,
	"if-unmodified-since":         43,
	"last-modified":               44,
	"link":                        45,
	"location":                    46,
	"max-forwards":                47,
	"proxy-authenticate":          48,
	"proxy-authorization":         49,
	"range":                       50,
	"referer":                     51,
	"refresh":                     52,
	"retry-after":                 53,
	"server":                      54,
	"set-cookie":                  55,
	"strict-transport-security":   56,
	"transfer-encoding":           57,
	"user-agent":                  58,
	"vary":                        59,
	"via":                         60,
	"www-authenticate":            61,
}

var staticTableEncodingWithValues = map[string]int{
	":method:GET":                   2,
	":method:POST":                  3,
	":path:/":                       4,
	":path:/index.html":             5,
	":scheme:http":                  6,
	":scheme:https":                 7,
	":status:200":                   8,
	":status:204":                   9,
	":status:206":                   10,
	":status:304":                   11,
	":status:400":                   12,
	":status:404":                   13,
	":status:500":                   14,
	"accept-encoding:gzip, deflate": 16,
}

var huffmanCodes = [][2]uint32{
	{0x1ff8, 13},
	{0x7fffd8, 23},
	{0xfffffe2, 28},
	{0xfffffe3, 28},
	{0xfffffe4, 28},
	{0xfffffe5, 28},
	{0xfffffe6, 28},
	{0xfffffe7, 28},
	{0xfffffe8, 28},
	{0xffffea, 24},
	{0x3ffffffc, 30},
	{0xfffffe9, 28},
	{0xfffffea, 28},
	{0x3ffffffd, 30},
	{0xfffffeb, 28},
	{0xfffffec, 28},
	{0xfffffed, 28},
	{0xfffffee, 28},
	{0xfffffef, 28},
	{0xffffff0, 28},
	{0xffffff1, 28},
	{0xffffff2, 28},
	{0x3ffffffe, 30},
	{0xffffff3, 28},
	{0xffffff4, 28},
	{0xffffff5, 28},
	{0xffffff6, 28},
	{0xffffff7, 28},
	{0xffffff8, 28},
	{0xffffff9, 28},
	{0xffffffa, 28},
	{0xffffffb, 28},
	{0x14, 6},
	{0x3f8, 10},
	{0x3f9, 10},
	{0xffa, 12},
	{0x1ff9, 13},
	{0x15, 6},
	{0xf8, 8},
	{0x7fa, 11},
	{0x3fa, 10},
	{0x3fb, 10},
	{0xf9, 8},
	{0x7fb, 11},
	{0xfa, 8},
	{0x16, 6},
	{0x17, 6},
	{0x18, 6},
	{0x0, 5},
	{0x1, 5},
	{0x2, 5},
	{0x19, 6},
	{0x1a, 6},
	{0x1b, 6},
	{0x1c, 6},
	{0x1d, 6},
	{0x1e, 6},
	{0x1f, 6},
	{0x5c, 7},
	{0xfb, 8},
	{0x7ffc, 15},
	{0x20, 6},
	{0xffb, 12},
	{0x3fc, 10},
	{0x1ffa, 13},
	{0x21, 6},
	{0x5d, 7},
	{0x5e, 7},
	{0x5f, 7},
	{0x60, 7},
	{0x61, 7},
	{0x62, 7},
	{0x63, 7},
	{0x64, 7},
	{0x65, 7},
	{0x66, 7},
	{0x67, 7},
	{0x68, 7},
	{0x69, 7},
	{0x6a, 7},
	{0x6b, 7},
	{0x6c, 7},
	{0x6d, 7},
	{0x6e, 7},
	{0x6f, 7},
	{0x70, 7},
	{0x71, 7},
	{0x72, 7},
	{0xfc, 8},
	{0x73, 7},
	{0xfd, 8},
	{0x1ffb, 13},
	{0x7fff0, 19},
	{0x1ffc, 13},
	{0x3ffc, 14},
	{0x22, 6},
	{0x7ffd, 15},
	{0x3, 5},
	{0x23, 6},
	{0x4, 5},
	{0x24, 6},
	{0x5, 5},
	{0x25, 6},
	{0x26, 6},
	{0x27, 6},
	{0x6, 5},
	{0x74, 7},
	{0x75, 7},
	{0x28, 6},
	{0x29, 6},
	{0x2a, 6},
	{0x7, 5},
	{0x2b, 6},
	{0x76, 7},
	{0x2c, 6},
	{0x8, 5},
	{0x9, 5},
	{0x2d, 6},
	{0x77, 7},
	{0x78, 7},
	{0x79, 7},
	{0x7a, 7},
	{0x7b, 7},
	{0x7ffe, 15},
	{0x7fc, 11},
	{0x3ffd, 14},
	{0x1ffd, 13},
	{0xffffffc, 28},
	{0xfffe6, 20},
	{0x3fffd2, 22},
	{0xfffe7, 20},
	{0xfffe8, 20},
	{0x3fffd3, 22},
	{0x3fffd4, 22},
	{0x3fffd5, 22},
	{0x7fffd9, 23},
	{0x3fffd6, 22},
	{0x7fffda, 23},
	{0x7fffdb, 23},
	{0x7fffdc, 23},
	{0x7fffdd, 23},
	{0x7fffde, 23},
	{0xffffeb, 24},
	{0x7fffdf, 23},
	{0xffffec, 24},
	{0xffffed, 24},
	{0x3fffd7, 22},
	{0x7fffe0, 23},
	{0xffffee, 24},
	{0x7fffe1, 23},
	{0x7fffe2, 23},
	{0x7fffe3, 23},
	{0x7fffe4, 23},
	{0x1fffdc, 21},
	{0x3fffd8, 22},
	{0x7fffe5, 23},
	{0x3fffd9, 22},
	{0x7fffe6, 23},
	{0x7fffe7, 23},
	{0xffffef, 24},
	{0x3fffda, 22},
	{0x1fffdd, 21},
	{0xfffe9, 20},
	{0x3fffdb, 22},
	{0x3fffdc, 22},
	{0x7fffe8, 23},
	{0x7fffe9, 23},
	{0x1fffde, 21},
	{0x7fffea, 23},
	{0x3fffdd, 22},
	{0x3fffde, 22},
	{0xfffff0, 24},
	{0x1fffdf, 21},
	{0x3fffdf, 22},
	{0x7fffeb, 23},
	{0x7fffec, 23},
	{0x1fffe0, 21},
	{0x1fffe1, 21},
	{0x3fffe0, 22},
	{0x1fffe2, 21},
	{0x7fffed, 23},
	{0x3fffe1, 22},
	{0x7fffee, 23},
	{0x7fffef, 23},
	{0xfffea, 20},
	{0x3fffe2, 22},
	{0x3fffe3, 22},
	{0x3fffe4, 22},
	{0x7ffff0, 23},
	{0x3fffe5, 22},
	{0x3fffe6, 22},
	{0x7ffff1, 23},
	{0x3ffffe0, 26},
	{0x3ffffe1, 26},
	{0xfffeb, 20},
	{0x7fff1, 19},
	{0x3fffe7, 22},
	{0x7ffff2, 23},
	{0x3fffe8, 22},
	{0x1ffffec, 25},
	{0x3ffffe2, 26},
	{0x3ffffe3, 26},
	{0x3ffffe4, 26},
	{0x7ffffde, 27},
	{0x7ffffdf, 27},
	{0x3ffffe5, 26},
	{0xfffff1, 24},
	{0x1ffffed, 25},
	{0x7fff2, 19},
	{0x1fffe3, 21},
	{0x3ffffe6, 26},
	{0x7ffffe0, 27},
	{0x7ffffe1, 27},
	{0x3ffffe7, 26},
	{0x7ffffe2, 27},
	{0xfffff2, 24},
	{0x1fffe4, 21},
	{0x1fffe5, 21},
	{0x3ffffe8, 26},
	{0x3ffffe9, 26},
	{0xffffffd, 28},
	{0x7ffffe3, 27},
	{0x7ffffe4, 27},
	{0x7ffffe5, 27},
	{0xfffec, 20},
	{0xfffff3, 24},
	{0xfffed, 20},
	{0x1fffe6, 21},
	{0x3fffe9, 22},
	{0x1fffe7, 21},
	{0x1fffe8, 21},
	{0x7ffff3, 23},
	{0x3fffea, 22},
	{0x3fffeb, 22},
	{0x1ffffee, 25},
	{0x1ffffef, 25},
	{0xfffff4, 24},
	{0xfffff5, 24},
	{0x3ffffea, 26},
	{0x7ffff4, 23},
	{0x3ffffeb, 26},
	{0x7ffffe6, 27},
	{0x3ffffec, 26},
	{0x3ffffed, 26},
	{0x7ffffe7, 27},
	{0x7ffffe8, 27},
	{0x7ffffe9, 27},
	{0x7ffffea, 27},
	{0x7ffffeb, 27},
	{0xffffffe, 28},
	{0x7ffffec, 27},
	{0x7ffffed, 27},
	{0x7ffffee, 27},
	{0x7ffffef, 27},
	{0x7fffff0, 27},
	{0x3ffffee, 26},
	{0x3fffffff, 30},
}

type Header struct {
	Name  string
	Value string

	Sensitive bool
}

var ErrIntegerValueTooLarge = errors.New("integer value larger than max value")
var ErrIntegerEncodedLengthTooLong = errors.New("integer encoded length is too long")
var ErrStringLiteralLengthTooLong = errors.New("string literal length is too long")

var DefaultMaxIntegerValue = ((1 << 32) - 1)
var DefaultMaxIntegerEncodedLength = 6
var DefaultMaxStringLiteralLength = 1024 * 64

type Encoder struct {
	dynamicTable                  []Header
	dynamicTableSizeMax           int
	dynamicTableSizeCurrent       int
	pendingDynamicTableSizeUpdate bool
}

// A decoder is stateful and updates the internal compression context during processing
// of header blocks.
//
// If HTTP/2 is used, a single decoder instance must be used during the lifetime of a connection, see:
// https://tools.ietf.org/html/rfc7540#section-4.3
type Decoder struct {
	dynamicTable            []Header
	dynamicTableSizeMax     int
	dynamicTableSizeCurrent int

	integerValueMax         int
	integerEncodedLengthMax int
	stringLiteralLengthMax  int
}

type bitReader struct {
	buf      []byte
	index    int
	bitIndex int
}

func newBitReader(buf []byte) *bitReader {
	return &bitReader{
		buf:      buf,
		index:    0,
		bitIndex: 0,
	}
}

var ErrHuffmanDecodeFailure = errors.New("invalid huffman code encountered")

func (br *bitReader) PeekBits(numBits int) (int, int) {
	var n int = 0
	var idx int = br.index
	var bitIdx int = br.bitIndex
	for x := numBits; x >= 0; {
		for y := 0; y < 8; y++ {
			var bit int = 0
			if ((br.buf[idx] << uint(bitIdx)) & (1 << 7)) == (1 << 7) {
				bit = 1
			}
			n |= (bit << uint(x-1))

			bitIdx += 1
			if bitIdx == 8 {
				bitIdx = 0
				idx += 1
				if idx == len(br.buf) {
					return n, (numBits - x + 1)
				}
			}
			x -= 1
		}
	}
	return n, numBits
}

func (br *bitReader) BitsAvailable() int {
	bytes := len(br.buf) - br.index
	return (8 * bytes) - br.bitIndex
}

func (br *bitReader) ConsumeBits(numBits int) {
	br.index += (numBits + br.bitIndex) / 8
	br.bitIndex = (numBits + br.bitIndex) % 8
}

// Encodes the specified data with Huffman codes in HPACK
func HuffmanEncode(data []byte) []byte {
	encoded := make([]byte, 0)
	var currentByte byte = 0
	currentBits := 0
	for _, b := range data {
		entry := huffmanCodes[b]
		code := entry[0]
		bits := int(entry[1])
		bitsRemaining := bits

		for bitsRemaining > 0 {
			if (code>>uint(bitsRemaining-1))&1 == 1 {
				currentByte |= 1
			}
			bitsRemaining -= 1
			currentBits += 1
			if currentBits == 8 {
				encoded = append(encoded, currentByte)
				currentByte = 0
				currentBits = 0
			} else {
				currentByte <<= 1
			}
		}
	}
	if currentBits > 0 && currentBits < 8 {
		padding := huffmanCodes[256]
		currentByte <<= 7 - uint(currentBits)
		currentByte |= byte(padding[0] >> (padding[1] - uint32(8-currentBits)))
		encoded = append(encoded, currentByte)
	}
	return encoded
}

// Decodes the huffman encoded data
func HuffmanDecode(encoded []byte) ([]byte, error) {
	decoded := make([]byte, 0)

	bitReader := newBitReader(encoded)
	for bitReader.BitsAvailable() >= 5 {
		n, bitsRead := bitReader.PeekBits(32)
		code := int32(n)
		decode_success := false

		table := lookupTable
		for bitIdx := 0; bitIdx < 32; bitIdx += 8 {
			entry := table[(code>>(24-uint(bitIdx)))&0xff]
			if entry != nil {
				if entry.nextTable != nil {
					table = entry.nextTable
				} else {
					if bitsRead >= int(entry.bits) {
						decoded = append(decoded, []byte{byte(entry.symbol)}...)
					}
					bitReader.ConsumeBits(int(entry.bits))
					decode_success = true
					break
				}
			}
		}
		if !decode_success {
			if bitsRead <= 7 {
				break
			} else {
				return nil, ErrHuffmanDecodeFailure
			}
		}
	}
	return decoded, nil
}

const (
	headerFieldIndexed                 = 128
	headerFieldLiteralIncrementalIndex = 64
	headerFieldDynamicSizeUpdate       = 32
	headerFieldLiteralNeverIndexed     = 16
	headerFieldLiteralNotIndexed       = 0
)

const (
	huffmanEncoded = 1 << 7
)

func NewEncoder(dynamicTableSizeMax int) *Encoder {
	return &Encoder{
		dynamicTableSizeMax:           dynamicTableSizeMax,
		dynamicTableSizeCurrent:       0,
		pendingDynamicTableSizeUpdate: false,
	}
}

func NewDecoder(dynamicTableSizeMax int) *Decoder {
	return &Decoder{
		dynamicTableSizeMax:     dynamicTableSizeMax,
		dynamicTableSizeCurrent: 0,
		integerEncodedLengthMax: DefaultMaxIntegerEncodedLength,
		integerValueMax:         DefaultMaxIntegerValue,
		stringLiteralLengthMax:  DefaultMaxStringLiteralLength,
	}
}

func (decoder *Decoder) readPrefixedLengthString(buf []byte, prefixLength int) (remainingBuf []byte, str string, err error) {
	if len(buf) == 0 {
		return buf, "", fmt.Errorf("ran out of data while decoding string literal")
	}
	rest, huffman, length, err := decoder.DecodeInteger(buf, prefixLength)
	if err != nil {
		return buf, "", err
	}

	if length > decoder.stringLiteralLengthMax {
		return buf, "", ErrStringLiteralLengthTooLong
	}

	if huffman&huffmanEncoded == huffmanEncoded {
		if len(rest) < length {
			return nil, "", fmt.Errorf("ran out of data while decoding huffman encoded data")
		}
		decoded, err := HuffmanDecode(rest[:length])
		if err != nil {
			return rest, "", err
		}
		return rest[length:], string(decoded), nil
	} else {
		if len(rest) < length {
			return nil, "", fmt.Errorf("ran out of data while decoding string literal")
		}
		return rest[length:], string(rest[:length]), nil
	}
}

func (decoder *Decoder) getIndexedNameValue(index int) (string, string, error) {
	if index > len(staticTable) {
		dynamicIndex := index - len(staticTable)
		if dynamicIndex > len(decoder.dynamicTable) {
			return "", "", fmt.Errorf("index %d not found in dynamic table", index)
		}
		return decoder.dynamicTable[dynamicIndex-1].Name, decoder.dynamicTable[dynamicIndex-1].Value, nil
	}
	if index <= 0 {
		return "", "", fmt.Errorf("invalid index %d", index)
	}
	return staticTable[index-1][0], staticTable[index-1][1], nil
}

// Updates the decoder's dynamic table maximum size and evicts any
// headers if more space is needed to resize to newMaxSize.
func (decoder *Decoder) SetDynamicTableMaxSize(newMaxSize int) {
	decoder.dynamicTableSizeMax = newMaxSize
	decoder.evictEntries(0, newMaxSize)
}

// Sets the largest integer that is allowed, anything > value will result in an error
func (decoder *Decoder) SetMaxIntegerValue(value int) {
	decoder.integerValueMax = value
}

// Sets the maximum bytes allowed for encoding a single integer
func (decoder *Decoder) SetMaxIntegerEncodedLength(length int) {
	decoder.integerEncodedLengthMax = length
}

// Sets the maximum length of a string literal
// For compressed string literals the length check will be against the
// compressed length, not the uncompressed length
func (decoder *Decoder) SetMaxStringLiteralLength(length int) {
	decoder.stringLiteralLengthMax = length
}

// Finds the header in the table.
// Returns the index and a bool indicating if the entry includes the value also.
// If the entry wasn't found the index returned is -1
func (encoder *Encoder) findHeaderInTable(name string, value string) (int, bool) {
	var entry int
	var ok bool

	if value != "" {
		entry, ok = staticTableEncodingWithValues[name+":"+value]
		if ok {
			return entry, true
		}
	}

	for x, header := range encoder.dynamicTable {
		if header.Name == name && header.Value == value {
			return len(staticTable) + x + 1, true
		}
	}

	entry, ok = staticTableEncoding[name]
	if ok {
		return entry, false
	}
	return -1, false
}

// Updates the encoder's dynamic table maximum size and evicts any
// headers if more space is needed to resize to newMaxSize.
//
// After this call the next header field that is encoded will include
// a dynamic table size update
func (encoder *Encoder) SetDynamicTableMaxSize(newMaxSize int) {
	encoder.dynamicTableSizeMax = newMaxSize
	encoder.evictEntries(0, newMaxSize)
	encoder.pendingDynamicTableSizeUpdate = true
}

func findStaticEntryInTable(name string) int {
	entry, ok := staticTableEncoding[name]
	if ok {
		return entry
	}
	return -1
}

// This is a convenience function that encodes a list of headers
// into a header block using Huffman compression and with incremental
// indexing enabled.
//
// If a header is marked as Sensitive it will be encoded as a
// never indexed header field
func (encoder *Encoder) Encode(headers []Header) ([]byte, error) {
	return encoder.encode(headers, true)
}

func encodeLiteralString(str string, prefixLength int, huffman bool) []byte {
	encoded := make([]byte, 0)

	var value []byte
	if huffman {
		value = HuffmanEncode([]byte(str))
	} else {
		value = []byte(str)
	}
	valueLen := encodeInteger(len(value), prefixLength)

	if huffman {
		valueLen[0] |= huffmanEncoded
	}
	encoded = append(encoded, valueLen...)
	encoded = append(encoded, value...)
	return encoded
}

// Encodes a header without Indexing and returns the encoded header field
//
// https://tools.ietf.org/html/rfc7541#appendix-C.2.2
func (encoder *Encoder) EncodeNoDynamicIndexing(header Header, huffman bool) ([]byte, error) {
	return encoder.encodeHeaderField(header, huffman, false)
}

// Encodes a header with Indexing and returns the encoded header field
//
// https://tools.ietf.org/html/rfc7541#appendix-C.2.1
func (encoder *Encoder) EncodeIndexed(header Header, huffman bool) ([]byte, error) {
	return encoder.encodeHeaderField(header, huffman, true)
}

func (encoder *Encoder) encodeHeaderField(header Header, huffman bool, addDynamicIndex bool) ([]byte, error) {
	encoded := make([]byte, 0)

	if encoder.pendingDynamicTableSizeUpdate {
		newSize := encodeInteger(encoder.dynamicTableSizeMax, 5)
		newSize[0] |= headerFieldDynamicSizeUpdate
		encoded = append(encoded, newSize...)
		encoder.pendingDynamicTableSizeUpdate = false
	}

	if header.Sensitive {
		index := findStaticEntryInTable(header.Name)
		if index != -1 {
			indexed := encodeInteger(index, 4)
			indexed[0] |= headerFieldLiteralNeverIndexed
			encoded = append(encoded, indexed...)
		} else {
			indexed := encodeInteger(0, 4)
			indexed[0] |= headerFieldLiteralNeverIndexed
			encoded = append(encoded, indexed...)
			encoded = append(encoded, encodeLiteralString(header.Name, 7, huffman)...)
		}

		encoded = append(encoded, encodeLiteralString(header.Value, 7, huffman)...)
	} else {
		index, valueIndexed := encoder.findHeaderInTable(header.Name, header.Value)
		if index != -1 && valueIndexed {
			indexed := encodeInteger(index, 7)
			indexed[0] |= headerFieldIndexed
			encoded = append(encoded, indexed...)
		} else {
			var indexed []byte
			if index == -1 {
				indexed = encodeInteger(0, 6)
			} else {
				indexed = encodeInteger(index, 6)
			}

			if addDynamicIndex {
				indexed[0] |= headerFieldLiteralIncrementalIndex
				encoder.addNewDynamicEntry(header.Name, header.Value)
			} else {
				indexed[0] |= headerFieldLiteralNotIndexed
			}

			encoded = append(encoded, indexed...)
			if index == -1 {
				encoded = append(encoded, encodeLiteralString(header.Name, 7, huffman)...)
			}

			encoded = append(encoded, encodeLiteralString(header.Value, 7, huffman)...)
		}
	}
	return encoded, nil
}

func (encoder *Encoder) encode(headers []Header, huffman bool) ([]byte, error) {
	encoded := make([]byte, 0)
	for _, header := range headers {
		enc, err := encoder.EncodeIndexed(header, huffman)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, enc...)
	}
	return encoded, nil
}

// Parsers the HPACK header block and returns list of headers
// with the order preserved from the order in the block.
func (decoder *Decoder) Decode(block []byte) ([]Header, error) {
	headers := make([]Header, 0)
	buf := block
	for len(buf) > 0 {
		var header *Header
		var err error

		buf, header, err = decoder.parseHeaderField(buf)
		if err != nil {
			return nil, err
		}
		if header != nil {
			headers = append(headers, *header)
		}
	}
	return headers, nil
}

// Returns true if there is enough space to accomadate additionalSize
func (encoder *Encoder) evictEntries(additionalSize int, maxSize int) bool {
	for encoder.dynamicTableSizeCurrent+additionalSize > maxSize {
		if len(encoder.dynamicTable) == 0 {
			return false
		}

		evictedEntry := encoder.dynamicTable[len(encoder.dynamicTable)-1]
		encoder.dynamicTableSizeCurrent -= (32 + len(evictedEntry.Name) + len(evictedEntry.Value))
		encoder.dynamicTable = encoder.dynamicTable[:len(encoder.dynamicTable)-1]
	}
	return true
}

// Returns true if there is enough space to accomadate additionalSize
func (decoder *Decoder) evictEntries(additionalSize int, maxSize int) bool {
	for decoder.dynamicTableSizeCurrent+additionalSize > maxSize {
		if len(decoder.dynamicTable) == 0 {
			return false
		}

		evictedEntry := decoder.dynamicTable[len(decoder.dynamicTable)-1]
		decoder.dynamicTableSizeCurrent -= (32 + len(evictedEntry.Name) + len(evictedEntry.Value))
		decoder.dynamicTable = decoder.dynamicTable[:len(decoder.dynamicTable)-1]
	}
	return true
}

func (encoder *Encoder) addNewDynamicEntry(name string, value string) {
	entrySize := (32 + len(name) + len(value))

	if !encoder.evictEntries(entrySize, encoder.dynamicTableSizeMax) {
		return
	}
	encoder.dynamicTableSizeCurrent += entrySize

	encoder.dynamicTable = append([]Header{
		{
			Name:  name,
			Value: value,
		},
	}, encoder.dynamicTable...)
}

func (decoder *Decoder) addNewDynamicEntry(name string, value string) {
	entrySize := (32 + len(name) + len(value))

	if !decoder.evictEntries(entrySize, decoder.dynamicTableSizeMax) {
		return
	}
	decoder.dynamicTableSizeCurrent += entrySize

	decoder.dynamicTable = append([]Header{
		{
			Name:  name,
			Value: value,
		},
	}, decoder.dynamicTable...)
}

func (decoder *Decoder) parseHeaderFieldIndexed(encoded []byte) ([]byte, *Header, error) {
	rest, _, index, err := decoder.DecodeInteger(encoded, 7)
	if err != nil {
		return nil, nil, err
	}

	name, value, err := decoder.getIndexedNameValue(index)
	if err != nil {
		return nil, nil, err
	}
	return rest, &Header{Name: name, Value: value}, nil
}

func (decoder *Decoder) parseHeaderFieldIncrementalIndex(encoded []byte) ([]byte, *Header, error) {
	rest, _, index, err := decoder.DecodeInteger(encoded, 6)
	if err != nil {
		return nil, nil, err
	}

	var name string
	if index == 0 {
		rest, name, err = decoder.readPrefixedLengthString(rest, 7)
		if err != nil {
			return nil, nil, err
		}
	} else {
		name, _, err = decoder.getIndexedNameValue(index)
		if err != nil {
			return nil, nil, err
		}
	}

	rest, value, err := decoder.readPrefixedLengthString(rest, 7)
	if err != nil {
		return nil, nil, err
	}

	decoder.addNewDynamicEntry(name, value)
	return rest, &Header{Name: name, Value: value}, nil
}

func (decoder *Decoder) parseDynamicSizeUpdate(encoded []byte) ([]byte, error) {
	consumed, _, size, err := decoder.DecodeInteger(encoded, 5)
	if err != nil {
		return nil, err
	}
	if size > decoder.dynamicTableSizeMax {
		return consumed, fmt.Errorf("can't resize dynamic table to %d in an update to a value greater than the current size, %d", size, decoder.dynamicTableSizeCurrent)
	}
	decoder.SetDynamicTableMaxSize(size)
	return consumed, nil
}

func (decoder *Decoder) parseHeaderFieldNotIndexed(encoded []byte) ([]byte, *Header, error) {
	rest, _, index, err := decoder.DecodeInteger(encoded, 4)
	if err != nil {
		return nil, nil, err
	}
	if index == 0 {
		rest, name, err := decoder.readPrefixedLengthString(rest, 7)
		if err != nil {
			return nil, nil, err
		}

		rest, value, err := decoder.readPrefixedLengthString(rest, 7)
		if err != nil {
			return nil, nil, err
		}

		return rest, &Header{Name: name, Value: value}, nil

	} else {
		name, _, err := decoder.getIndexedNameValue(index)
		if err != nil {
			return nil, nil, err
		}

		rest, value, err := decoder.readPrefixedLengthString(rest, 7)
		if err != nil {
			return nil, nil, err
		}

		return rest, &Header{Name: name, Value: value}, nil
	}
}

func (decoder *Decoder) parseHeaderField(encoded []byte) ([]byte, *Header, error) {
	if encoded[0]&headerFieldIndexed == headerFieldIndexed {
		return decoder.parseHeaderFieldIndexed(encoded)
	} else if encoded[0]&headerFieldLiteralIncrementalIndex == headerFieldLiteralIncrementalIndex {
		return decoder.parseHeaderFieldIncrementalIndex(encoded)
	} else if encoded[0]&headerFieldDynamicSizeUpdate == headerFieldDynamicSizeUpdate {
		rest, err := decoder.parseDynamicSizeUpdate(encoded)
		if err != nil {
			return rest, nil, err
		}
		return rest, nil, nil
	} else if encoded[0]&headerFieldLiteralNeverIndexed == headerFieldLiteralNeverIndexed {
		rest, header, err := decoder.parseHeaderFieldNotIndexed(encoded)
		if err != nil {
			return rest, header, err
		} else {
			header.Sensitive = true
			return rest, header, err
		}
	} else if encoded[0]&headerFieldLiteralNotIndexed == headerFieldLiteralNotIndexed {
		return decoder.parseHeaderFieldNotIndexed(encoded)
	} else {
		panic(fmt.Errorf("unknown type: %02x", encoded[0]))
	}
}

func (decoder *Decoder) DecodeInteger(buf []byte, prefixLength int) (remainingBuf []byte, maskedFirstOctet int, number int, err error) {
	return decodeInteger(buf, prefixLength, decoder.integerValueMax, decoder.integerEncodedLengthMax)
}

func decodeInteger(buf []byte, prefixLength int, integerMax int, encodedLengthMax int) (remainingBuf []byte, maskedFirstOctet int, number int, err error) {
	if prefixLength < 1 || prefixLength > 8 {
		panic("prefix length in bits must be >= 1 and <= 8")
	}
	mask := (1<<uint(prefixLength) - 1)
	n := mask & int(buf[0])
	prefix := int(buf[0]) &^ mask
	if n != mask {
		return buf[1:], prefix, n, nil
	} else {
		idx := 1
		m := 0
		for {
			if idx == len(buf) {
				panic("ran out of data while reading HPACK integer")
			}
			n += (int(buf[idx]) & 127) * int(math.Pow(2, float64(m)))
			if buf[idx]&(1<<7) == 0 {
				if n > integerMax {
					return nil, 0, 0, ErrIntegerValueTooLarge
				}
				return buf[idx+1:], prefix, n, nil
			}
			m += 7
			idx += 1
			if idx == encodedLengthMax {
				return nil, 0, 0, ErrIntegerEncodedLengthTooLong
			}
		}
	}
}

// Encodes number with the specified prefix length in number of bits.
//
// See https://tools.ietf.org/html/rfc7541#section-5.1
func (encoder *Encoder) EncodeInteger(number int, prefixLength int) []byte {
	return encodeInteger(number, prefixLength)
}

func encodeInteger(number int, prefixLength int) []byte {
	if prefixLength < 1 || prefixLength > 8 {
		panic("prefix length in bits must be >= 1 and <= 8")
	}
	if number < int(math.Pow(2, float64(prefixLength)))-1 {
		return []byte{byte(number)}
	} else {
		i := number
		buf := []byte{byte(int(math.Pow(2, float64(prefixLength))) - 1)}
		i -= (int(math.Pow(2, float64(prefixLength))) - 1)
		for i >= 128 {
			buf = append(buf, byte((i%128)+128))
			i /= 128
		}
		buf = append(buf, byte(i))
		return buf
	}
}
