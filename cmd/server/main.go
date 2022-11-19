package main

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"io"
	"math/rand"
	"net/http"
	"time"

	"github.com/matsuyoshi30/ocspmock"
	"golang.org/x/crypto/ocsp"
)

func main() {
	h := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		b, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		req, err := ocsp.ParseRequest(b)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		rb, _ := createResponse(req)
		w.Write(rb)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", h)

	s := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	s.ListenAndServe()
}

func createResponse(r *ocsp.Request) ([]byte, error) {
	issuerCert, _ := hex.DecodeString(ocspmock.IssuerCertHex)
	issuer, err := x509.ParseCertificate(issuerCert)
	if err != nil {
		return nil, err
	}

	responderCert, _ := hex.DecodeString(responderCertHex)
	responder, err := x509.ParseCertificate(responderCert)
	if err != nil {
		return nil, err
	}

	responderPrivateKeyDER, _ := hex.DecodeString(responderPrivateKeyHex)
	responderPrivateKey, err := x509.ParsePKCS1PrivateKey(responderPrivateKeyDER)
	if err != nil {
		return nil, err
	}

	extensionBytes, _ := hex.DecodeString(ocspExtensionValueHex)
	extensions := []pkix.Extension{
		{
			Id:       ocspExtensionOID,
			Critical: false,
			Value:    extensionBytes,
		},
	}

	thisUpdate := time.Now()
	nextUpdate := thisUpdate.AddDate(0, 0, 7)
	template := ocsp.Response{
		SerialNumber:    r.SerialNumber,
		ThisUpdate:      thisUpdate,
		NextUpdate:      nextUpdate,
		Certificate:     responder,
		ExtraExtensions: extensions,
		IssuerHash:      crypto.SHA256,
	}

	rand.Seed(thisUpdate.Unix())
	rv := rand.Intn(100)
	if rv < 80 {
		template.Status = ocsp.Good
	} else if rv < 90 {
		template.Status = ocsp.Revoked
		template.RevokedAt = thisUpdate.AddDate(0, 0, -3)
		template.RevocationReason = ocsp.RemoveFromCRL
	} else {
		template.Status = ocsp.Unknown
	}

	rb, err := ocsp.CreateResponse(issuer, responder, template, responderPrivateKey)
	if err != nil {
		return nil, err
	}

	return rb, nil
}

// from https://cs.opensource.google/go/x/crypto/+/refs/tags/v0.3.0:ocsp/ocsp_test.go;drc=0ec7e8322c090be3a94a90823b9ae085541f5f1e;l=631

var ocspExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

const ocspExtensionValueHex = "0403000000"

// Key and certificate for the OCSP responder were not taken from the Thawte
// responder, since CreateResponse requires that we have the private key.
// Instead, they were generated randomly.
const responderPrivateKeyHex = "308204a40201000282010100e8155f2d3e6f2e8d14c62a788bd462f9f844e7a6977c83ef" +
	"1099f0f6616ec5265b56f356e62c5400f0b06a2e7945a82752c636df32a895152d6074df" +
	"1701dc6ccfbcbec75a70bd2b55ae2be7e6cad3b5fd4cd5b7790ab401a436d3f5f346074f" +
	"fde8a99d5b723350f0a112076614b12ef79c78991b119453445acf2416ab0046b540db14" +
	"c9fc0f27b8989ad0f63aa4b8aefc91aa8a72160c36307c60fec78a93d3fddf4259902aa7" +
	"7e7332971c7d285b6a04f648993c6922a3e9da9adf5f81508c3228791843e5d49f24db2f" +
	"1290bafd97e655b1049a199f652cd603c4fafa330c390b0da78fbbc67e8fa021cbd74eb9" +
	"6222b12ace31a77dcf920334dc94581b02030100010282010100bcf0b93d7238bda329a8" +
	"72e7149f61bcb37c154330ccb3f42a85c9002c2e2bdea039d77d8581cd19bed94078794e" +
	"56293d601547fc4bf6a2f9002fe5772b92b21b254403b403585e3130cc99ccf08f0ef81a" +
	"575b38f597ba4660448b54f44bfbb97072b5a2bf043bfeca828cf7741d13698e3f38162b" +
	"679faa646b82abd9a72c5c7d722c5fc577a76d2c2daac588accad18516d1bbad10b0dfa2" +
	"05cfe246b59e28608a43942e1b71b0c80498075121de5b900d727c31c42c78cf1db5c0aa" +
	"5b491e10ea4ed5c0962aaf2ae025dd81fa4ce490d9d6b4a4465411d8e542fc88617e5695" +
	"1aa4fc8ea166f2b4d0eb89ef17f2b206bd5f1014bf8fe0e71fe62f2cccf102818100f2dc" +
	"ddf878d553286daad68bac4070a82ffec3dc4666a2750f47879eec913f91836f1d976b60" +
	"daf9356e078446dafab5bd2e489e5d64f8572ba24a4ba4f3729b5e106c4dd831cc2497a7" +
	"e6c7507df05cb64aeb1bbc81c1e340d58b5964cf39cff84ea30c29ec5d3f005ee1362698" +
	"07395037955955655292c3e85f6187fa1f9502818100f4a33c102630840705f8c778a47b" +
	"87e8da31e68809af981ac5e5999cf1551685d761cdf0d6520361b99aebd5777a940fa64d" +
	"327c09fa63746fbb3247ec73a86edf115f1fe5c83598db803881ade71c33c6e956118345" +
	"497b98b5e07bb5be75971465ec78f2f9467e1b74956ca9d4c7c3e314e742a72d8b33889c" +
	"6c093a466cef0281801d3df0d02124766dd0be98349b19eb36a508c4e679e793ba0a8bef" +
	"4d786888c1e9947078b1ea28938716677b4ad8c5052af12eb73ac194915264a913709a0b" +
	"7b9f98d4a18edd781a13d49899f91c20dbd8eb2e61d991ba19b5cdc08893f5cb9d39e5a6" +
	"0629ea16d426244673b1b3ee72bd30e41fac8395acac40077403de5efd028180050731dd" +
	"d71b1a2b96c8d538ba90bb6b62c8b1c74c03aae9a9f59d21a7a82b0d572ef06fa9c807bf" +
	"c373d6b30d809c7871df96510c577421d9860c7383fda0919ece19996b3ca13562159193" +
	"c0c246471e287f975e8e57034e5136aaf44254e2650def3d51292474c515b1588969112e" +
	"0a85cc77073e9d64d2c2fc497844284b02818100d71d63eabf416cf677401ebf965f8314" +
	"120b568a57dd3bd9116c629c40dc0c6948bab3a13cc544c31c7da40e76132ef5dd3f7534" +
	"45a635930c74326ae3df0edd1bfb1523e3aa259873ac7cf1ac31151ec8f37b528c275622" +
	"48f99b8bed59fd4da2576aa6ee20d93a684900bf907e80c66d6e2261ae15e55284b4ed9d" +
	"6bdaa059"

const responderCertHex = "308202e2308201caa003020102020101300d06092a864886f70d01010b05003019311730" +
	"150603550403130e4f43535020526573706f6e646572301e170d31353031333031353530" +
	"33335a170d3136303133303135353033335a3019311730150603550403130e4f43535020" +
	"526573706f6e64657230820122300d06092a864886f70d01010105000382010f00308201" +
	"0a0282010100e8155f2d3e6f2e8d14c62a788bd462f9f844e7a6977c83ef1099f0f6616e" +
	"c5265b56f356e62c5400f0b06a2e7945a82752c636df32a895152d6074df1701dc6ccfbc" +
	"bec75a70bd2b55ae2be7e6cad3b5fd4cd5b7790ab401a436d3f5f346074ffde8a99d5b72" +
	"3350f0a112076614b12ef79c78991b119453445acf2416ab0046b540db14c9fc0f27b898" +
	"9ad0f63aa4b8aefc91aa8a72160c36307c60fec78a93d3fddf4259902aa77e7332971c7d" +
	"285b6a04f648993c6922a3e9da9adf5f81508c3228791843e5d49f24db2f1290bafd97e6" +
	"55b1049a199f652cd603c4fafa330c390b0da78fbbc67e8fa021cbd74eb96222b12ace31" +
	"a77dcf920334dc94581b0203010001a3353033300e0603551d0f0101ff04040302078030" +
	"130603551d25040c300a06082b06010505070309300c0603551d130101ff04023000300d" +
	"06092a864886f70d01010b05000382010100718012761b5063e18f0dc44644d8e6ab8612" +
	"31c15fd5357805425d82aec1de85bf6d3e30fce205e3e3b8b795bbe52e40a439286d2288" +
	"9064f4aeeb150359b9425f1da51b3a5c939018555d13ac42c565a0603786a919328f3267" +
	"09dce52c22ad958ecb7873b9771d1148b1c4be2efe80ba868919fc9f68b6090c2f33c156" +
	"d67156e42766a50b5d51e79637b7e58af74c2a951b1e642fa7741fec982cc937de37eff5" +
	"9e2005d5939bfc031589ca143e6e8ab83f40ee08cc20a6b4a95a318352c28d18528dcaf9" +
	"66705de17afa19d6e8ae91ddf33179d16ebb6ac2c69cae8373d408ebf8c55308be6c04d9" +
	"3a25439a94299a65a709756c7a3e568be049d5c38839"
