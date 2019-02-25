package pki

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func normalizeSerial(serial string) string {
	return strings.Replace(strings.ToLower(serial), ":", "-", -1)
}

func parseExtKeyUsageParameter(unparsed []string) ([]x509.ExtKeyUsage, error) {
	extKeyUsages := make([]x509.ExtKeyUsage, 0, len(unparsed))
	oidRegexp := regexp.MustCompile(`(\d+\.)+\d`)
	idRegexp := regexp.MustCompile(`\d+`)
	for _, s := range unparsed {
		switch {
		case oidRegexp.MatchString(s):
			oid := asn1Parse(s)
			eku, ok := extKeyUsageFromOID(oid)
			if !ok {
				return nil, fmt.Errorf("unknow oid: %s", s)
			}
			extKeyUsages = append(extKeyUsages, eku)
		case idRegexp.MatchString(s):
			eku, err := ekuParse(s)
			if err != nil {
				return nil, err
			}
			extKeyUsages = append(extKeyUsages, eku)
		default:
			return nil, fmt.Errorf("unknow extKeyUsage format: %s", s)
		}
	}
	return extKeyUsages, nil
}

var (
	oidExtKeyUsageAny                            = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtKeyUsageServerAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser                      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping                   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtKeyUsageMicrosoftServerGatedCrypto     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageNetscapeServerGatedCrypto      = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
	oidExtKeyUsageMicrosoftCommercialCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
	oidExtKeyUsageMicrosoftKernelCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
)

var extKeyUsageOIDs = []struct {
	extKeyUsage x509.ExtKeyUsage
	oid         asn1.ObjectIdentifier
}{
	{x509.ExtKeyUsageAny, oidExtKeyUsageAny},
	{x509.ExtKeyUsageServerAuth, oidExtKeyUsageServerAuth},
	{x509.ExtKeyUsageClientAuth, oidExtKeyUsageClientAuth},
	{x509.ExtKeyUsageCodeSigning, oidExtKeyUsageCodeSigning},
	{x509.ExtKeyUsageEmailProtection, oidExtKeyUsageEmailProtection},
	{x509.ExtKeyUsageIPSECEndSystem, oidExtKeyUsageIPSECEndSystem},
	{x509.ExtKeyUsageIPSECTunnel, oidExtKeyUsageIPSECTunnel},
	{x509.ExtKeyUsageIPSECUser, oidExtKeyUsageIPSECUser},
	{x509.ExtKeyUsageTimeStamping, oidExtKeyUsageTimeStamping},
	{x509.ExtKeyUsageOCSPSigning, oidExtKeyUsageOCSPSigning},
	{x509.ExtKeyUsageMicrosoftServerGatedCrypto, oidExtKeyUsageMicrosoftServerGatedCrypto},
	{x509.ExtKeyUsageNetscapeServerGatedCrypto, oidExtKeyUsageNetscapeServerGatedCrypto},
	{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, oidExtKeyUsageMicrosoftCommercialCodeSigning},
	{x509.ExtKeyUsageMicrosoftKernelCodeSigning, oidExtKeyUsageMicrosoftKernelCodeSigning},
}

func extKeyUsageFromOID(oid asn1.ObjectIdentifier) (eku x509.ExtKeyUsage, ok bool) {
	for _, pair := range extKeyUsageOIDs {
		if oid.Equal(pair.oid) {
			return pair.extKeyUsage, true
		}
	}
	return
}

func checkExtKeyUsage(eku x509.ExtKeyUsage) bool {
	for _, pair := range extKeyUsageOIDs {
		if pair.extKeyUsage == eku {
			return true
		}
	}
	return false
}

func asn1Parse(s string) asn1.ObjectIdentifier {
	intString := strings.Split(s, ".")
	ints := make([]int, len(intString))
	for i, is := range intString {
		id, _ := strconv.Atoi(is)
		ints[i] = id
	}
	return ints
}

func ekuParse(s string) (eku x509.ExtKeyUsage, err error) {
	i, _ := strconv.Atoi(s)
	eku = x509.ExtKeyUsage(i)
	if checkExtKeyUsage(eku) {
		return
	}
	err = fmt.Errorf("unknow eku: %s", s)
	return
}
