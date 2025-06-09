package tlschecker

import (
	"encoding/json"
	"testing"
)

func TestSingleCertCheck(t *testing.T) {
	//certificatechecker.StoreSummaries()
	var certTest CertResult = CheckCertificate("sectigo.com")
	PrettyPrint(certTest)
}

func PrettyPrint(v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	println(string(b))
}
