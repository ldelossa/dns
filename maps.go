package dns

// DNS QRTypes
var QRTypes = map[uint8]string{
	0: "Query",
	1: "Response",
}

// OpCodes
var OpCodes = map[uint8]string{
	0: "Query",
	1: "IQuery",
	2: "Status",
	3: "Unassigned",
	4: "Notify",
	5: "Update",
}

// RCodes
var RCodes = map[uint8]string{
	0:  "NoError",
	1:  "FormErr",
	2:  "ServFail",
	3:  "NXDomain",
	4:  "NotImp",
	5:  "Refused",
	6:  "YXDomain",
	7:  "YXRRSet",
	8:  "NXRRSet",
	9:  "NotAuth",
	10: "NotZone",
	16: "BADVERS",
	17: "BADSIG",
	18: "BADTIME",
	19: "BADMODE",
	20: "BADNAME",
	21: "BADALG",
	22: "BADTRUNC",
	23: "BADCOOKIE",
}

// QTypes
var QTypes = map[uint16]string{
	1:     "A",
	28:    "AAAA",
	18:    "AFSDB",
	42:    "APL",
	257:   "CAA",
	60:    "CDNSKEY",
	59:    "CDS",
	37:    "CERT",
	5:     "CNAME",
	49:    "DHCID",
	32769: "DLV",
	32:    "DNAME",
	48:    "DNSKEY",
	43:    "DS",
	55:    "HIP",
	45:    "IPSECKEY",
	25:    "KEY",
	36:    "KX",
	29:    "LOC",
	15:    "MX",
	35:    "NAPTR",
	2:     "NS",
	47:    "NSEC",
	50:    "NSEC3",
	51:    "NSEC3PARAM",
	61:    "OPENPGPKEY",
	12:    "PTR",
	46:    "RRSIG",
	17:    "RP",
	24:    "SIG",
	6:     "SOA",
	33:    "SRV",
	44:    "SSHFP",
	32768: "TA",
	249:   "TKEY",
	52:    "TLSA",
	250:   "TSIG",
	16:    "TXT",
	256:   "URI",
}

// QClasses
var QClasses = map[uint16]string{
	0:   "Reserved",
	1:   "Internet",
	3:   "Chaos",
	4:   "Hesiod",
	254: "QCLASS NONE",
	255: "QCLASS *(ANY)",
}
