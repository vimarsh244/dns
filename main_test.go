package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestFindZoneRecords(t *testing.T) {
	// Setup a test zone
	zone = map[string][]rr{
		"example.com.": {
			{Name: "example.com.", Type_: type_a, Rdata: net.ParseIP("1.2.3.4").To4(), TTL: 123},
			{Name: "example.com.", Type_: type_mx, Rdata: []byte{0, 10, 3, 'm', 'a', 'i', 'l', 0}, TTL: 234},
		},
		"*.wild.example.com.": {
			{Name: "*.wild.example.com.", Type_: type_a, Rdata: net.ParseIP("5.6.7.8").To4(), TTL: 345},
		},
		"cname.example.com.": {
			{Name: "cname.example.com.", Type_: type_cname, Rdata: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, TTL: 456},
		},
		"ipv6.example.com.": {
			{Name: "ipv6.example.com.", Type_: type_aaaa, Rdata: net.ParseIP("2001:db8::1").To16(), TTL: 567},
		},
		"txt.example.com.": {
			{Name: "txt.example.com.", Type_: type_txt, Rdata: []byte{11, 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'}, TTL: 678},
		},
		"mx.example.com.": {
			{Name: "mx.example.com.", Type_: type_mx, Rdata: []byte{0, 10, 4, 'm', 'a', 'i', 'l', 0}, TTL: 789},
		},
		"soa.example.com.": {
			{Name: "soa.example.com.", Type_: type_soa, Rdata: soaToRdata(&soaRdata{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 2023010101, Refresh: 3600, Retry: 1800, Expire: 604800, Minimum: 600}), TTL: 890},
		},
	}

	testCases := []struct {
		name         string
		query        string
		expectedType uint16
		expectedVal  string
		expectedTTL  uint32
	}{
		{
			name:         "A Record",
			query:        "example.com.",
			expectedType: type_a,
			expectedVal:  "1.2.3.4",
			expectedTTL:  123,
		},
		{
			name:         "Wildcard A Record",
			query:        "test.wild.example.com.",
			expectedType: type_a,
			expectedVal:  "5.6.7.8",
			expectedTTL:  345,
		},
		{
			name:         "CNAME Record",
			query:        "cname.example.com.",
			expectedType: type_cname,
			expectedVal:  "example.com",
			expectedTTL:  456,
		},
		{
			name:         "AAAA Record",
			query:        "ipv6.example.com.",
			expectedType: type_aaaa,
			expectedVal:  "2001:db8::1",
			expectedTTL:  567,
		},
		{
			name:         "TXT Record",
			query:        "txt.example.com.",
			expectedType: type_txt,
			expectedVal:  "hello world",
			expectedTTL:  678,
		},
		{
			name:         "MX Record",
			query:        "mx.example.com.",
			expectedType: type_mx,
			expectedVal:  "10 mail",
			expectedTTL:  789,
		},
		{
			name:         "SOA Record",
			query:        "soa.example.com.",
			expectedType: type_soa,
			expectedVal:  "ns1.example.com. hostmaster.example.com. 2023010101 3600 1800 604800 600",
			expectedTTL:  890,
		},
		{
			name:         "No Record",
			query:        "nonexistent.example.com.",
			expectedType: 0,
			expectedVal:  "",
			expectedTTL:  0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			answers := findZoneRecords(tc.query)

			if tc.expectedType == 0 {
				if len(answers) != 0 {
					t.Errorf("Expected no records for %s, but got %d", tc.query, len(answers))
				}
				return
			}

			if len(answers) == 0 {
				t.Fatalf("Expected records for %s, but got none", tc.query)
			}

			found := false
			for _, ans := range answers {
				if ans.Type_ == tc.expectedType {
					found = true
					var val string
					switch ans.Type_ {
					case type_a:
						val = net.IP(ans.Rdata).String()
					case type_aaaa:
						val = net.IP(ans.Rdata).String()
					case type_cname:
						val = decode_name(ans.Rdata)
					case type_txt:
						val = string(ans.Rdata[1:])
					case type_mx:
						preference := int(ans.Rdata[0])<<8 | int(ans.Rdata[1])
						exchange := decode_name(ans.Rdata[2:])
						val = strconv.Itoa(preference) + " " + exchange
					case type_soa:
						soa := decode_soa_rdata(ans.Rdata)
						if soa != nil {
							val = soa.MName + " " + soa.RName + " " + strconv.FormatUint(uint64(soa.Serial), 10) + " " +
								strconv.FormatUint(uint64(soa.Refresh), 10) + " " +
								strconv.FormatUint(uint64(soa.Retry), 10) + " " +
								strconv.FormatUint(uint64(soa.Expire), 10) + " " +
								strconv.FormatUint(uint64(soa.Minimum), 10)
						}
					}

					if !strings.Contains(val, tc.expectedVal) {
						t.Errorf("Expected value %s for %s, but got %s", tc.expectedVal, tc.query, val)
					}
					if ans.TTL != tc.expectedTTL {
						t.Errorf("Expected TTL %d for %s, but got %d", tc.expectedTTL, tc.query, ans.TTL)
					}
				}
			}

			if !found {
				t.Errorf("Expected to find record of type %d for %s, but did not", tc.expectedType, tc.query)
			}
		})
	}
}

func soaToRdata(soa *soaRdata) []byte {
	buf := &bytes.Buffer{}
	write_name(buf, soa.MName)
	write_name(buf, soa.RName)
	binary.Write(buf, binary.BigEndian, soa.Serial)
	binary.Write(buf, binary.BigEndian, soa.Refresh)
	binary.Write(buf, binary.BigEndian, soa.Retry)
	binary.Write(buf, binary.BigEndian, soa.Expire)
	binary.Write(buf, binary.BigEndian, soa.Minimum)
	return buf.Bytes()
}
