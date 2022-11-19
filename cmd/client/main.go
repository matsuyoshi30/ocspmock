package main

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/crypto/ocsp"

	"github.com/matsuyoshi30/ocspmock"
)

var status = []string{"Good", "Revoked", "Unknown"}

func main() {
	leafCert, _ := hex.DecodeString(ocspmock.LeafCertHex)
	leaf, err := x509.ParseCertificate(leafCert)
	if err != nil {
		fmt.Println(err)
		return
	}

	issuerCert, _ := hex.DecodeString(ocspmock.IssuerCertHex)
	issuer, err := x509.ParseCertificate(issuerCert)
	if err != nil {
		fmt.Println(err)
		return
	}

	ocspReqBytes, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	resp, err := http.Post("http://localhost:8080", "application/ocsp-request", bytes.NewBuffer(ocspReqBytes))
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	r, err := ocsp.ParseResponse(b, nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("OCSP Response Status: %q\n", status[r.Status])
	fmt.Printf("OCSP Response SerialNumber: %v\n", r.SerialNumber)
	fmt.Printf("OCSP Response ProducedAt: %q\n", r.ProducedAt)
	fmt.Printf("OCSP Response ThisUpdate: %q\n", r.ThisUpdate)
	fmt.Printf("OCSP Response NextUpdate: %q\n", r.NextUpdate)
	fmt.Printf("OCSP Response RevokedAt: %q\n", r.RevokedAt)
}
