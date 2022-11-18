package main

import (
	"fmt"
	"io"
	"net/http"

	"golang.org/x/crypto/ocsp"
)

var status = []string{"Good", "Revoked", "Unknown"}

func main() {
	resp, err := http.Get("http://localhost:8080")
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
