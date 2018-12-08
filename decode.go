package dns

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// flags and masks
const (
	OpCodeMask   = byte(0x78)
	RCodeMask    = byte(0x0F)
	ANLabelMask  = byte(0xC0)
	ANLengthMask = byte(0x3F)
	QRFlag       = byte(1 << 7)
	AAFlag       = byte(1 << 2)
	TCFlag       = byte(1 << 1)
	RDFlag       = byte(1 << 0)
	RAFlag       = byte(1 << 7)
)

// Query struct which will contain easy accessible information about the Query payload.
// most of this info is derived from the embeded Header struct
type Query struct {
	Header    Header
	Question  Question
	Type      string
	OpCode    string
	RCode     string
	Authority bool
	ANCount   int // int is larger then field in header so this is safe
	QDCount   int
	TCP       bool // whether query was made over TCP or not
}

func (d *Query) String() string {
	s := fmt.Sprintf(`
	ID: %d
	Type: %s
	OpCode: %s
	RCode: %s
	Authority: %t
	Answer Count: %d
	Question Count: %d
	TCP: %t
	`, d.Header.ID, d.Type, d.OpCode, d.RCode, d.Authority, d.ANCount, d.QDCount, d.TCP)

	return s
}

// Header represents the header of a valid DNS payload. Will have raw info parsed from
// the bytes making up the DNS header
type Header struct {
	// ID to match corresponding request or response with
	ID uint16
	// one bit field specifying if this is a request or a response
	QR int
	// opcode indicating what kind of query this DNS payload is
	OpCode uint8
	// Authority Answer - is the response from an authority
	AA int
	// TrunCation - specifies message was truncated
	TC int
	// recursion desired
	RD int
	// recurion Available
	RA int
	// response code
	RCode int
	// numbers of entries in the questions section
	QDCount uint16
	// number of resource records in the answers section
	ANCount uint16
	// number of name server records in the authority record section
	NSCount uint16
	// number of resource records in the additional records section
	ARCount uint16
	// tcp has length header
	Length uint16
}

type Question struct {
	// decoded and concated hostname
	QueryName string
	// type of record being requested
	Type string
	// class of query
	Class string
}

func DecodePayload(buffer []byte, tcp bool) (*Query, error) {
	d := &Query{
		TCP: tcp,
	}

	// tcp has length header
	if tcp {
		d.Header.Length = binary.BigEndian.Uint16(buffer[:2])
		buffer = buffer[2:] // discard length
	}

	// obtain ID - first 16 bits
	d.Header.ID = binary.BigEndian.Uint16(buffer[:2])
	buffer = buffer[2:] // discard ID

	flags := buffer[:2] // get flags
	buffer = buffer[2:] // discard Flags from working buffer

	// pass flags buffer and DNS object to decodeFlags
	decodeFlags(flags, d)

	// obtain counts, 4 16 bit fields
	d.Header.QDCount = binary.BigEndian.Uint16(buffer[:2])
	d.QDCount = int(d.Header.QDCount)
	d.Header.ANCount = binary.BigEndian.Uint16(buffer[2:4])
	d.ANCount = int(d.Header.ANCount)
	d.Header.NSCount = binary.BigEndian.Uint16(buffer[4:6])
	d.Header.ARCount = binary.BigEndian.Uint16(buffer[6:8])

	// discard header
	buffer = buffer[8:]

	if d.Type == "Query" {
		err := decodeQuestion(buffer, d)
		if err != nil {
			return nil, err
		}
	}

	return d, nil
}

// decodeQuetion decodes the question portion of a DNS Query. currently this only supports parsing
// labels and not pointers. with a bit more time i would encorporate the header compression parsing also
func decodeQuestion(buffer []byte, d *Query) error {
	buffCopy := buffer
	q := Question{}

	buffLen := len(buffer)
	var b strings.Builder
	// where to seek the buffer to once finished with host name parsing
	var trunc int

	// while i is in upper bound of buffLen check if we see a label. If we do
	// slice the buffer from current index + 1 to length reported by label. write
	// the sliced bytes to our string builder and append ".". set i to the immediate next byte
	// after the reported length
	for i := 0; i < buffLen; {
		if 0 == (buffer[i] & ANLabelMask) {
			strLen := int(buffer[i])
			strBytes := buffer[i+1 : i+1+strLen]

			_, err := b.Write(strBytes)
			if err != nil {
				return err
			}
			_, err = b.WriteString(".")
			if err != nil {
				return err
			}

			i = i + int(strLen) + 1
		}

		// null means end of hostname parsing
		if 0x00 == buffer[i] {
			trunc = i + 1 // give clue to truncate array one past null byte to discard all labels
			break
		}
	}

	// truncate buffCopy
	buffCopy = buffCopy[trunc:]

	q.QueryName = b.String()
	t, ok := QTypes[binary.BigEndian.Uint16(buffer[:2])]
	if ok {
		q.Type = t
	}
	c, ok := QTypes[binary.BigEndian.Uint16(buffer[2:4])]
	if ok {
		q.Class = c
	}

	// add Question to passed in Query
	d.Question = q

	return nil
}

// decodeFlags expects a buffer with the first two bytes containing the flags
// portion of a DNS payload header.
func decodeFlags(buffer []byte, dns *Query) {
	flag1 := buffer[0]
	flag2 := buffer[1]

	// is QRFlag set
	if 0 != (flag1 & QRFlag) {
		// bit is set
		dns.Header.QR = 1
		dns.Type = QRTypes[1]
	} else {
		// zero value will take care of QR = 0
		dns.Type = QRTypes[0]
	}

	// get Opcode by masking and right shift by 3
	optCode := (flag1 & OpCodeMask) >> 3
	dns.Header.OpCode = uint8(optCode)
	optCodeStr, ok := OpCodes[uint8(optCode)]
	if ok {
		dns.OpCode = optCodeStr
	}

	// is AA flag set
	if 0 != (flag1 & AAFlag) {
		dns.Header.AA = 1
		dns.Authority = true
	}

	// is TC flag set
	if 0 != (flag1 & TCFlag) {
		dns.Header.TC = 1
	}

	// is RD flag set
	if 0 != (flag1 & RDFlag) {
		dns.Header.RD = 1
	}

	// is RA flag set
	if 0 != (flag2 & RDFlag) {
		dns.Header.RA = 1
	}

	// get RCode with mask, no need to shift as it's at least sig bits already
	rCode := (flag2 & RCodeMask)
	dns.Header.RCode = int(rCode)
	rCodeStr, ok := RCodes[uint8(rCode)]
	if ok {
		dns.RCode = rCodeStr
	}

}
