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
	stringRegexp := regexp.MustCompile(`[a-z]+`)
	for _, s := range unparsed {
		switch {
		case oidRegexp.MatchString(s):
			oid, _ := stringToOid(s)
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
		case stringRegexp.MatchString(s):
			eku, known := findEkuByName(s)
			if !known {
				return nil, fmt.Errorf("unknown eku: %s", s)
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
	name        string
}{
	{x509.ExtKeyUsageAny, oidExtKeyUsageAny, "any"},
	{x509.ExtKeyUsageServerAuth, oidExtKeyUsageServerAuth, "serverauth"},
	{x509.ExtKeyUsageClientAuth, oidExtKeyUsageClientAuth, "clientauth"},
	{x509.ExtKeyUsageCodeSigning, oidExtKeyUsageCodeSigning, "codesigning"},
	{x509.ExtKeyUsageEmailProtection, oidExtKeyUsageEmailProtection, "emailprotection"},
	{x509.ExtKeyUsageIPSECEndSystem, oidExtKeyUsageIPSECEndSystem, "ipsecendsystem"},
	{x509.ExtKeyUsageIPSECTunnel, oidExtKeyUsageIPSECTunnel, "ipsectunnel"},
	{x509.ExtKeyUsageIPSECUser, oidExtKeyUsageIPSECUser, "ipsecuser"},
	{x509.ExtKeyUsageTimeStamping, oidExtKeyUsageTimeStamping, "timestamping"},
	{x509.ExtKeyUsageOCSPSigning, oidExtKeyUsageOCSPSigning, "ocspsigning"},
	{x509.ExtKeyUsageMicrosoftServerGatedCrypto, oidExtKeyUsageMicrosoftServerGatedCrypto, "microsoftservergatedcrypto"},
	{x509.ExtKeyUsageNetscapeServerGatedCrypto, oidExtKeyUsageNetscapeServerGatedCrypto, "netscapeservergatedcrypto"},
	{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, oidExtKeyUsageMicrosoftCommercialCodeSigning, "microsoftcommercialcodesigning"},
	{x509.ExtKeyUsageMicrosoftKernelCodeSigning, oidExtKeyUsageMicrosoftKernelCodeSigning, "microsoftkernelcodesigning"},
}

func extKeyUsageFromOID(oid asn1.ObjectIdentifier) (eku x509.ExtKeyUsage, ok bool) {
	for _, triplet := range extKeyUsageOIDs {
		if oid.Equal(triplet.oid) {
			return triplet.extKeyUsage, true
		}
	}
	return
}

func checkExtKeyUsage(eku x509.ExtKeyUsage) bool {
	for _, triplet := range extKeyUsageOIDs {
		if triplet.extKeyUsage == eku {
			return true
		}
	}
	return false
}

func findEkuByName(name string) (x509.ExtKeyUsage, bool) {
	name = strings.ToLower(name)
	for _, triplet := range extKeyUsageOIDs {
		if triplet.name == name {
			return triplet.extKeyUsage, true
		}
	}
	return 0, false
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

func compareEkuList(a, b []x509.ExtKeyUsage) bool {
	//todo: compare
	return true
}
