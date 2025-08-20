package tlschecker

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestSingleCertCheck(t *testing.T) {
	//certificatechecker.StoreSummaries()
	var certTest CertResult = CheckCertificate("www.stihl.com")
	//var certTest CertResult = CheckCertificate("blog.cloudflare.com")
	PrettyPrint(certTest)
	var rootStores = StoreSummaries()
	fmt.Println(rootStores)
}

func PrettyPrint(v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	println(string(b))
}
