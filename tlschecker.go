package tlschecker

import (
	_ "bytes"
	"context"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	_ "strconv"
	"strings"
	"time"

	"github.com/bogdanovich/dns_resolver"
	"github.com/domainr/dnsr"
	"github.com/weppos/publicsuffix-go/publicsuffix"
	"golang.org/x/net/http2"

	utls "github.com/refraction-networking/utls"
)

//go:embed truststores/*.pem
var trustStoresDir embed.FS

// Global regular expressions
var (
	reg *regexp.Regexp
	//timeoutS time.Duration = 3 * time.Second
	//timeoutDeadline time.Duration = 3 * time.Second
	//connRetry       int           = 2
)

// Trust stores
var (
	mozStore    *x509.CertPool
	msStore     *x509.CertPool
	appleStore  *x509.CertPool
	chromeStore *x509.CertPool
)

// Trust store files
var storeUpdate = "7-Nov-2025"

/*
var (

	mozFile    string = "truststores/Mozilla-PEM-30072025.pem"
	msFile     string = "truststores/MS-PEM-30072025.pem"
	appleFile  string = "truststores/Apple-PEM-30072025.pem"
	chromeFile string = "truststores/Chrome-PEM-30072025.pem"

)
*/
var (
	mozCerts    *[]byte
	msCerts     *[]byte
	appleCerts  *[]byte
	chromeCerts *[]byte
)

func init() {
	//	Compile regular expressions for IP-address check and HTTP-Header server-token parsing
	reg = regexp.MustCompile(`[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+`)

	//	Load the root stores from the PEM files
	//mozCerts, _ := os.ReadFile(mozFile)
	mozCerts, _ := trustStoresDir.ReadFile("truststores/Mozilla-PEM-07112025.pem")
	mozStore = x509.NewCertPool()
	mozStore.AppendCertsFromPEM(mozCerts)

	appleCerts, _ := trustStoresDir.ReadFile("truststores/Apple-PEM-07112025.pem")
	appleStore = x509.NewCertPool()
	appleStore.AppendCertsFromPEM(appleCerts)

	msCerts, _ := trustStoresDir.ReadFile("truststores/MS-PEM-07112025.pem")
	msStore = x509.NewCertPool()
	msStore.AppendCertsFromPEM(msCerts)

	chromeCerts, _ := trustStoresDir.ReadFile("truststores/Chrome-PEM-07112025.pem")
	chromeStore = x509.NewCertPool()
	chromeStore.AppendCertsFromPEM(chromeCerts)
}

// - - - - -

/*
Summary info?
expired?
trusted?
mismatch?
installed?root included?
or not

TLS version
cipher suites

expiry of chain
sels-signed root in chain


*/

type TLSCheck struct {
	ScanInformation ScanInfo       `json:"scaninformation"`
	CertInformation CertInfo       `json:"certinformation"`
	ConnInformation ConnectionInfo `json:"conninformation"`
	ErrorMessage    string         `json:"errormessage"`
}

type ScanInfo struct {
	ScanTime     int    `json:"scantime"`
	ScanDuration int    `json:"scanduration"`
	ScanInput    string `json:"scaninput"`
	RawInput     string `json:"rawinput"`
	PublicSuffix string `json:"publicsuffix"`
	PortNumber   int    `json:"portnumber"`
	IPAddress    string `json:"ipaddress"`
	HostName     string `json:"hostname"`
}

type CertInfo struct {
	SubjectInformation SubjectInfo `json:"subjectinformation"`
	IssuerInformation  IssuerInfo  `json:"issuerinformation"`
	TrustInformation   TrustInfo   `json:"trustinformation"`
	PEMCertificate     string      `json:"pemcertificate"`
	PEMChain           string      `json:"pemchain,omitempty"`
	NotBefore          int         `json:"notbefore"`
	NotAfter           int         `json:"notafter"`
	KeySize            int         `json:"keysize"`
	KeyType            string      `json:"keytype"`
	SigAlg             string      `json:"sigalg"`
	PolicyOIDS         string      `json:"policyoids"`
	AIAUrl             string      `json:"aiaurl"`
	OCSPUrl            string      `json:"ocspurl"`
	CRLUrl             string      `json:"crlurl"`
	FingerprintSHA256  string      `json:"fingerprintsha256"`
	SerialNumber       string      `json:"serialnumber"`
	ValidationType     string      `json:"valdationtype"`
	ProductType        string      `json:"producttype"`
	Validity           string      `json:"validity"`
	NameMismatch       string      `json:"namemistmatch"`
	RevocationStatus   string      `json:"revocationstatus"`
}

type IssuerInfo struct {
	FullIssuer  string `json:"fullissuer"`
	IssuerCN    string `json:"issuercn"`
	IssuerBrand string `json:"issuerbrand,omitempty"`
}

type TrustInfo struct {
	AppleTrust  string `json:"appletrust"`
	MozTrust    string `json:"moztrust"`
	MSTrust     string `json:"mstrust"`
	GoogleTrust string `json:"googletrust"`
}

type SubjectInfo struct {
	CN            string `json:"cn,omitempty"`
	O             string `json:"o,omitempty"`
	OU            string `json:"ou,omitempty"`
	L             string `json:"l,omitempty"`
	ST            string `json:"st,omitempty"`
	C             string `json:"c,omitempty"`
	SANS          string `json:"sans,omitempty"`
	CertSANSCount int    `json:"certsanscount"`
	FullSubject   string `json:"fullsubject"`
}

type ConnectionInfo struct {
	ServerType   string       `json:"servertype,omitempty"`
	OCSPStaple   string       `json:"ocspstaple,omitempty"`
	HTTPHeaders  []HTTPHeader `json:"httpheaders,omitempty"`
	NSRecords    string       `json:"nsrecords,omitempty"`
	MXRecords    string       `json:"mxrecords,omitempty"`
	CAARecords   string       `json:"caarecords,omitempty"`
	RevDNSRecord string       `json:"revdnsrecord,omitempty"`
}

type HTTPHeader struct {
	Header      string `json:"header,omitempty"`
	HeaderValue string `json:"headervalue,omitempty"`
}

// Certificate structure
type CertResult struct {
	ScanTime     int
	ScanDuration int
	ScanInput    string
	RawAddress   string
	PublicSuffix string
	PortNumber   string
	IPAddress    string
	HostName     string

	PEMCertificate string
	PEMChain       string
	NotBefore      int
	NotAfter       int
	KeySize        int
	KeyType        string
	SigAlg         string

	OCSPStaple string

	CertIssuerCN  string
	CertSubjectCN string

	CertCountry string
	CertSubject string

	CertFingerprintSHA256 string
	SerialNumber          string

	CertIssuer string
	CertSANS   string

	CertSANSCount int

	CertOrg string

	PolicyOIDS string

	ValidationType string

	Validity         string
	NameMismatch     string
	RevocationStatus string

	AIAUrl  string
	OCSPUrl string
	CRLUrl  string

	ServerType   string
	NSRecords    string
	MXRecords    string
	CAARecords   string
	RevDNSRecord string

	HTTPHeaders string

	TLSVersion string

	ScanTimings string

	MozTrust    string
	MSTrust     string
	AppleTrust  string
	GoogleTrust string

	CertificateOwner string

	ProductType string

	ErrorMessage string
}

func StoreSummaries() string {
	var storeSummary string
	storeSummary = fmt.Sprintf("Stores updated on: %v\n", storeUpdate)
	storeSummary += fmt.Sprintf("Apple Root Store: loaded %v certs.\n", len(appleStore.Subjects()))
	storeSummary += fmt.Sprintf("Microsoft Root Store: %v certs.\n", len(msStore.Subjects()))
	storeSummary += fmt.Sprintf("Mozilla Root Store: loaded %v certs.\n", len(mozStore.Subjects()))
	storeSummary += fmt.Sprintf("Chrome Root Store: loaded %v certs.\n", len(mozStore.Subjects()))
	return storeSummary
}

func CheckCertificate(address string) CertResult {
	// CertPool for the server-provided chain
	providedIntermediates := x509.NewCertPool()

	//	Input could be a full URI, or include the protocol
	var requestURI string

	if strings.Contains(address, "/") {
		u, err := url.Parse(address)
		if err == nil {
			requestURI = u.RequestURI()
			if requestURI == address {
				requestURI = ""
			}
			if requestURI == "/" {
				requestURI = ""
			}
			if u.Host != address {
				address = u.Host
			}
		}
	} else {
		requestURI = ""
	}

	//	Some variables and input-cleaning to begin with, and of course the start time marker
	startTime := int(time.Now().Unix())
	accurateStartTime := time.Now()
	var domainName, port, finalConnection string
	var thisCertificate CertResult
	thisCertificate.ScanTime = startTime
	address = strings.TrimSpace(address)
	thisCertificate.ScanInput = address

	//	address = 'raw' address from the input file
	//	we need to determine if it's an FQDN, IPv4 address, IPv6 address or any combination thereof with a ':port' appended...
	var hostPort = strings.Split(address, ":")
	//	Length of result is 1: No colons, hence no specified port. Assume 443.
	//	2: 1 colon, assume IPv4 or FQDN with specified hostname.
	//	>2: So many colons! Let's assume an IPv6 address. [Need to work out later about host to determine port - presumably > 7 colons = port specified?]
	if len(hostPort) == 1 {
		domainName = hostPort[0]
		port = "443"
	} else if len(hostPort) == 2 {
		domainName = hostPort[0]
		port = hostPort[1]
	} else {
		domainName = address
		port = "443"
	}
	if requestURI == port {
		requestURI = ""
	}
	//	PSL
	thisCertificate.PublicSuffix, _ = publicsuffix.Domain(domainName)

	//	Determine if the 'HostName' part is an IP address or not - if it's a domain, attempt a DNS lookup
	//	If we do DNS here (via a couple of packages including the amazing miekg's DNS) - then we hopefully avoid the cgo/host lookup threading problems
	//	Determination is done with a regexp. Yes, yes. I know.
	if reg.FindString(domainName) == "" {
		resolver := dns_resolver.New([]string{"8.8.8.8"})
		resolver.RetryTimes = 3
		ipAdd, err := resolver.LookupHost(domainName)
		//ipAdd, err := net.LookupIP(domainName)
		//ip, err := net.LookupHost(domainName)
		if err != nil {
			thisCertificate.ErrorMessage = "Failed DNS lookup"
			return thisCertificate
		}
		if len(ipAdd) >= 1 {
			resolvedIP := ipAdd[0].String()
			finalConnection = resolvedIP + ":" + port
			thisCertificate.IPAddress = resolvedIP
		} else {
			thisCertificate.ErrorMessage = "Failed DNS lookup"
			return thisCertificate
		}
	} else {
		finalConnection = domainName + ":" + port
		thisCertificate.IPAddress = domainName
	}

	thisCertificate.RawAddress = address
	thisCertificate.PortNumber = port
	thisCertificate.HostName = domainName

	//	Additional DNS lookups
	//	If the hostname starts www., trim that, otherwise leave it
	regDomainName := strings.TrimPrefix(domainName, "www.")
	r := dnsr.New(10000)
	var caaRecords, mxRecords, nsRecords, ptrRecords strings.Builder
	for _, rr := range r.Resolve(regDomainName, "CAA") {
		if rr.Type == "CAA" {
			caaRecords.WriteString(rr.Value + ",")
		}
	}
	for _, rr := range r.Resolve(regDomainName, "MX") {
		if rr.Type == "MX" {
			mxRecords.WriteString(rr.Value + ",")
		}
	}
	for _, rr := range r.Resolve(regDomainName, "NS") {
		if rr.Type == "NS" {
			nsRecords.WriteString(rr.Value + ",")
		}
	}
	ptrLookup, _ := net.LookupAddr(thisCertificate.IPAddress)
	for _, rr := range ptrLookup {
		ptrRecords.WriteString(rr + ",")
	}

	thisCertificate.NSRecords = strings.TrimSuffix(nsRecords.String(), ",")
	thisCertificate.MXRecords = strings.TrimSuffix(mxRecords.String(), ",")
	thisCertificate.CAARecords = strings.TrimSuffix(caaRecords.String(), ",")
	thisCertificate.RevDNSRecord = strings.TrimSuffix(ptrRecords.String(), ",")

	dnsLookupTime := time.Now()

	//	New new verion of TLS client using utls to avoid fingerprinting, and HTTP2 where necessary
	client, conn, err := CustomHTTPClient(domainName, finalConnection)
	if err != nil {
		thisCertificate.ErrorMessage = "Error creating TLS HTTP client" + err.Error()
		return thisCertificate
	}
	if requestURI != "" {
		domainName = domainName + requestURI
	}
	req, err := http.NewRequest("GET", "https://"+domainName, nil)
	if err != nil {
		thisCertificate.ErrorMessage = "Error making HTTP request" + err.Error()
		//return thisCertificate
	}
	response, err := client.Do(req)
	if err != nil {
		thisCertificate.ErrorMessage = "Error making HTTP request" + err.Error()
		//return thisCertificate
	}

	//	-	-	-	-	-

	/*if err != nil {
		thisCertificate.ErrorMessage = "Failed TCP connection / Connection refused" + err.Error()
		return thisCertificate
	}*/

	ipConnTime := time.Now()

	//	Check TLS version from connection (or the highest version, at least) - should implement proper testing of each version, but that might need multiple handshakes
	connState := conn.ConnectionState()

	switch connState.Version {
	case tls.VersionSSL30:
		thisCertificate.TLSVersion = "TLS 1.0 and up not supported"
	case tls.VersionTLS10:
		thisCertificate.TLSVersion = "TLS 1.1 and up not supported"
	case tls.VersionTLS11:
		thisCertificate.TLSVersion = "TLS 1.2 and up not supported"
	case tls.VersionTLS12:
		thisCertificate.TLSVersion = "TLS 1.3 not supported"
	case tls.VersionTLS13:
		thisCertificate.TLSVersion = "TLS 1.3 supported"
	}

	//	Log the OCSP response (in base64) if we are given one
	if len(conn.OCSPResponse()) != 0 {
		thisCertificate.OCSPStaple = base64.StdEncoding.EncodeToString(conn.OCSPResponse())
	}

	//	HTTP headers, separating out servertype
	var httpHeaders strings.Builder
	thisCertificate.ServerType = response.Header.Get("Server")
	for httpHeaderName, httpHeaderValues := range response.Header {
		var httpHeaderValueString strings.Builder
		for _, httpHeaderValue := range httpHeaderValues {
			httpHeaderValueString.WriteString(httpHeaderValue)
		}
		httpHeaders.WriteString(httpHeaderName + ": " + httpHeaderValueString.String() + ",")
	}
	thisCertificate.HTTPHeaders = strings.TrimSuffix(httpHeaders.String(), ",")

	defer response.Body.Close()

	httpHeaderTime := time.Now()

	defer conn.Close()

	var trustTestCert *x509.Certificate

	//	Loop each certificate in the PeerCertificates (from the server) and analyse each - grab subject info, SANs, key & KeySize, PEM version
	checkedCert := make(map[string]bool)
	i := 0
	certChain := ""
	for _, cert := range conn.ConnectionState().PeerCertificates {
		// Ensure that each unique certificate is checked only once per host.
		if _, checked := checkedCert[string(cert.Signature)]; checked {
			continue
		}
		checkedCert[string(cert.Signature)] = true

		if i == 0 {
			//	Put the whole subject (well, what is already formatted into a pkix.Name) into one string
			thisCertificate.CertSubject = fmt.Sprintf("%+v", cert.Subject.Names)
			thisCertificate.CertIssuer = fmt.Sprintf("%+v", cert.Issuer.Names)

			//	Other informational bits
			thisCertificate.CertSubjectCN = cert.Subject.CommonName
			thisCertificate.CertIssuerCN = cert.Issuer.CommonName
			thisCertificate.CertCountry = strings.Join(cert.Subject.Country, "")
			thisCertificate.CertSANS = strings.Join(cert.DNSNames, ",")
			thisCertificate.CertSANSCount = len(cert.DNSNames)
			thisCertificate.NotBefore = int(cert.NotBefore.Unix())
			thisCertificate.NotAfter = int(cert.NotAfter.Unix())
			thisCertificate.CertOrg = strings.Join(cert.Subject.Organization, "")

			//fmt.Printf("subject: %+v\n", cert.Subject)

			// Policy OIDs for EV checking
			PolicyOIDSString := fmt.Sprintf("%d", cert.PolicyIdentifiers)
			PolicyOIDS := strings.Replace(PolicyOIDSString, "[[", "", -1)
			PolicyOIDS = strings.Replace(PolicyOIDS, "]]", "", -1)
			PolicyOIDS = strings.Replace(PolicyOIDS, "] [", ",", -1)
			PolicyOIDS = strings.Replace(PolicyOIDS, " ", ".", -1)
			thisCertificate.PolicyOIDS = strings.TrimSpace(PolicyOIDS)

			switch cert.PublicKeyAlgorithm {
			case 0:
				thisCertificate.KeyType = "Unknown"
				thisCertificate.KeySize = 0
			case 1:
				thisCertificate.KeyType = "RSA"
				rsaKey, err := x509.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
				if err == nil {
					rsaPub := rsaKey.(*rsa.PublicKey)
					KeySize := rsaPub.N
					thisCertificate.KeySize = KeySize.BitLen()
				}
			case 2:
				thisCertificate.KeyType = "DSA"
				dsaKey, err := x509.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
				if err == nil {
					dsaPub := dsaKey.(*dsa.PublicKey)
					KeySize := dsaPub.Y
					thisCertificate.KeySize = KeySize.BitLen()
				}
			case 3:
				thisCertificate.KeyType = "ECDSA"
				ecdsaKey, err := x509.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
				if err == nil {
					ecdsaPub := ecdsaKey.(*ecdsa.PublicKey)
					KeySize := ecdsaPub.X
					thisCertificate.KeySize = KeySize.BitLen()
				}
			default:
				thisCertificate.KeyType = "Unknown"
				thisCertificate.KeySize = 0
			}

			switch cert.SignatureAlgorithm {
			case 0:
				thisCertificate.SigAlg = "UnknownSignatureAlgorithm"
			case 1:
				thisCertificate.SigAlg = "MD2WithRSA"
			case 2:
				thisCertificate.SigAlg = "MD5WithRSA"
			case 3:
				thisCertificate.SigAlg = "SHA1WithRSA"
			case 4:
				thisCertificate.SigAlg = "SHA256WithRSA"
			case 5:
				thisCertificate.SigAlg = "SHA384WithRSA"
			case 6:
				thisCertificate.SigAlg = "SHA512WithRSA"
			case 7:
				thisCertificate.SigAlg = "DSAWithSHA1"
			case 8:
				thisCertificate.SigAlg = "DSAWithSHA256"
			case 9:
				thisCertificate.SigAlg = "ECDSAWithSHA1"
			case 10:
				thisCertificate.SigAlg = "ECDSAWithSHA256"
			case 11:
				thisCertificate.SigAlg = "ECDSAWithSHA384"
			case 12:
				thisCertificate.SigAlg = "ECDSAWithSHA512"
			}

			thisCertificate.PEMCertificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
			trustTestCert = cert

			//	Cert fingerprint (SHA-256)
			thisCertificate.CertFingerprintSHA256 = strings.Replace(fmt.Sprintf("% X", sha256.Sum256(cert.Raw)), " ", ":", -1)

			//	Cert serial
			thisCertificate.SerialNumber = cert.SerialNumber.String()
		} else {
			certChain += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
			providedIntermediates.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		}

		sha256HashCert := sha256.New()
		sha256HashCert.Write(cert.Raw)
		//fmt.Println("Cert sha-256: ", hex.EncodeToString(sha256HashCert.Sum(nil)))
		if CertificateOwner[hex.EncodeToString(sha256HashCert.Sum(nil))] != "" {
			thisCertificate.CertificateOwner = CertificateOwner[hex.EncodeToString(sha256HashCert.Sum(nil))]
		}
		i++
	}

	//	Trust store checking
	//	Omit the 'dnsName' value in VerifyOptions - we do our own name-mismatch checking and want to keep separate - this is 'just' for path validation
	if mozStore != nil {
		opts := x509.VerifyOptions{
			Roots:         mozStore,
			Intermediates: providedIntermediates,
		}

		if _, err := trustTestCert.Verify(opts); err != nil {
			thisCertificate.MozTrust = "N"
		} else {
			thisCertificate.MozTrust = "Y"
		}
	}
	if msStore != nil {
		opts := x509.VerifyOptions{
			Roots:         msStore,
			Intermediates: providedIntermediates,
		}

		if _, err := trustTestCert.Verify(opts); err != nil {
			thisCertificate.MSTrust = "N"
		} else {
			thisCertificate.MSTrust = "Y"
		}
	}
	if appleStore != nil {
		opts := x509.VerifyOptions{
			Roots:         appleStore,
			Intermediates: providedIntermediates,
		}

		if _, err := trustTestCert.Verify(opts); err != nil {
			thisCertificate.AppleTrust = "N"
		} else {
			thisCertificate.AppleTrust = "Y"
		}
	}
	if chromeStore != nil {
		opts := x509.VerifyOptions{
			Roots:         chromeStore,
			Intermediates: providedIntermediates,
		}

		if _, err := trustTestCert.Verify(opts); err != nil {
			thisCertificate.GoogleTrust = "N"
		} else {
			thisCertificate.GoogleTrust = "Y"
		}
	}

	//	Add the chain of all certs provided by the server
	thisCertificate.PEMChain = certChain

	// Cert validation type - SS DV OV EV
	//	Self-signed: if CN is issuer, OR, if CN is in issuer (may produce small number of false positives?)
	//	No org in Subject - DV
	//	EV OID in the cert - EV
	//	Otherwise, OV?
	//	Should we factor trust in here too? What about a valid 'trusted' OV cert that simply wasn't installed fully?

	//	Split OIDs for testing
	PolicyOIDArray := strings.Split(thisCertificate.PolicyOIDS, ",")

	if thisCertificate.CertSubjectCN == thisCertificate.CertIssuerCN || strings.Contains(thisCertificate.CertIssuerCN, thisCertificate.CertSubjectCN) {
		thisCertificate.ValidationType = "SS"
	} else if thisCertificate.CertOrg == "" {
		thisCertificate.ValidationType = "DV"
	} else {
		for _, thisOID := range PolicyOIDArray {
			_, evOID := EVIssuers[thisOID]
			if evOID {
				thisCertificate.ValidationType = "EV"
			}
		}
		if thisCertificate.ValidationType != "EV" {
			thisCertificate.ValidationType = "OV"
		}
	}

	//	Certificate 'type' determination - single, wildcard, multi-domain
	if thisCertificate.CertSANSCount > 2 {
		if strings.Contains(thisCertificate.CertSANS, "*") {
			thisCertificate.ProductType = "MDC with Wildcard"
		} else {
			thisCertificate.ProductType = "MDC"
		}
	} else {
		if strings.Contains(thisCertificate.CertSANS, "*") {
			thisCertificate.ProductType = "Wildcard"
		} else {
			thisCertificate.ProductType = "Single"
		}
	}

	// Naming mis-match - using Go function
	if trustTestCert.VerifyHostname(thisCertificate.HostName) != nil {
		thisCertificate.NameMismatch = "Y"
	} else {
		thisCertificate.NameMismatch = "N"
	}

	//	CDPs, AIA
	thisCertificate.CRLUrl = strings.Join(trustTestCert.CRLDistributionPoints, ",")
	thisCertificate.AIAUrl = strings.Join(trustTestCert.IssuingCertificateURL, ",")
	thisCertificate.OCSPUrl = strings.Join(trustTestCert.OCSPServer, ",")

	// Dates
	if thisCertificate.NotAfter < int(time.Now().Unix()) {
		thisCertificate.Validity = "Expired"
	} else if thisCertificate.NotBefore > int(time.Now().Unix()) {
		thisCertificate.Validity = "Not yet valid"
	} else {
		thisCertificate.Validity = "Valid"
	}

	scanTime := time.Now()
	accurateScanDuration := int(scanTime.Sub(accurateStartTime) / time.Millisecond)
	thisCertificate.ScanDuration = accurateScanDuration

	timeForDNSLookup := int(dnsLookupTime.Sub(accurateStartTime) / time.Millisecond)
	timeForIPConnection := int(ipConnTime.Sub(dnsLookupTime) / time.Millisecond)
	timeForHTTPHeader := int(httpHeaderTime.Sub(ipConnTime) / time.Millisecond)

	scanTimings := fmt.Sprintf("Timings - DNS Lookup: %dms, Connection: %dms, HTTP Header: %dms, Scan processing: %dms", timeForDNSLookup, timeForIPConnection, timeForHTTPHeader, accurateScanDuration)
	thisCertificate.ScanTimings = scanTimings

	return thisCertificate
}

// CustomHTTPClient creates an HTTP client with uTLS for HTTP/1.1 or HTTP/2
func CustomHTTPClient(domainName string, ipAndPort string) (*http.Client, *utls.UConn, error) {
	// Client for collecting TLS connection state
	var savedConn *utls.UConn
	var combinedDial = domainName + "?" + ipAndPort

	utls.EnableWeakCiphers()

	// Create the dialer for both HTTP/1.1 and HTTP/2 clients
	dialer := &net.Dialer{
		Timeout:   3 * time.Second,
		KeepAlive: 3 * time.Second,
	}

	// Create a function to establish a uTLS connection
	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Split the FQDN and resolved IP/Port group
		//fmt.Println("debug dialTLS: ", addr)

		var nameComponents []string
		if strings.Contains(addr, "?") {
			nameComponents = strings.Split(addr, "?")
		} else {
			nameComponentsH1 := strings.Split(addr, ":")
			nameComponents = append(nameComponents, nameComponentsH1[0])
			nameComponents = append(nameComponents, addr)
		}

		// Standard TCP connection
		tcpConn, err := dialer.DialContext(ctx, network, nameComponents[1])
		if err != nil {
			return nil, err
		}

		// Create uTLS config
		config := &utls.Config{
			ServerName:         nameComponents[0],
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		}

		// Create uTLS client connection
		uTLSConn := utls.UClient(tcpConn, config, utls.HelloChrome_Auto)
		//uTLSConn := utls.UClient(tcpConn, config, utls.HelloSafari_Auto)
		//uTLSConn := utls.UClient(tcpConn, config, utls.HelloFirefox_Auto)
		//----
		/*
			cleanHex := `160301014b0100014703032ab68bea7ca19e1c07d6594e26b3c0265079321cc8c987a994c591114e29d08420cd819c68c6483cc85361815c9cab00b62f0f2b432d35ab0a6696b99f25e37fbe003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff010000c00000001a00180000157777772e616c6d756261736865722e636f6d2e7361000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000005000501000000000016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b0009080304030303020301002d00020101003300260024001d002054abd63d1359dfcbe500774b68fa1122ce46575a056bfc3e7f975c95f20d2663`

			// 2. Decode the cleaned hex string into a byte slice.
			openSSLHello, err := hex.DecodeString(cleanHex)
			if err != nil {
				fmt.Printf("Failed to decode hex string: %v", err)
			}
			uTLSConn := utls.UClient(&net.TCPConn{}, config, utls.HelloCustom)
			fingerprinter := &utls.Fingerprinter{}
			generatedSpec, err := fingerprinter.FingerprintClientHello(openSSLHello)
			if err != nil {
				fmt.Printf("Fingerprinting failed: %v", err)
			}
			if err := uTLSConn.ApplyPreset(generatedSpec); err != nil {
				fmt.Printf("Failed to generate spec: %v", err)
			}
		*/
		//----

		// Perform handshake
		if err := uTLSConn.HandshakeContext(ctx); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("uTLS handshake failed: %v", err)
		}

		// Save the connection for later state access
		savedConn = uTLSConn

		return uTLSConn, nil
	}

	// First check if server supports HTTP/2
	// We need to do a probe connection to determine this
	probeConn, err := dialTLS(context.Background(), "tcp", combinedDial)
	if err != nil {
		return nil, nil, fmt.Errorf("probe connection failed: %v", err)
	}
	defer probeConn.Close()

	// Get the ALPN protocol that was negotiated
	uTLSConn, ok := probeConn.(*utls.UConn)
	if !ok {
		return nil, nil, fmt.Errorf("failed to cast probe connection to uTLS connection")
	}

	// Get the negotiated protocol
	negotiatedProtocol := uTLSConn.ConnectionState().NegotiatedProtocol

	// Create HTTP client based on negotiated protocol
	if negotiatedProtocol == "h2" {
		// Create HTTP/2 client
		//fmt.Println("HTTP 2 client")
		h2Transport := &http2.Transport{
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return dialTLS(context.Background(), network, combinedDial)
			},
		}

		client := &http.Client{
			Transport: h2Transport,
			Timeout:   30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		return client, savedConn, nil
	} else {
		// Create HTTP/1.1 client
		//fmt.Println("HTTP 1.1 client")
		h1Transport := &http.Transport{
			DialTLSContext:      dialTLS,
			TLSHandshakeTimeout: 10 * time.Second,
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
		}

		client := &http.Client{
			Transport: h1Transport,
			Timeout:   30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		return client, savedConn, nil
	}
}

func FallbackGetCert(fqdn string) ([]*x509.Certificate, error) {
	// The address must include the port. For HTTPS, this is typically 443.
	addr := net.JoinHostPort(fqdn, "443")

	// Create a custom TLS configuration.
	// InsecureSkipVerify: true is the key part of this configuration. It tells the
	// client to bypass the normal certificate verification process, which includes
	// checking the certificate chain against a trusted root CA, verifying the
	// hostname, and checking the expiry date.
	//
	// WARNING: This should ONLY be used for diagnostic tools like this one.
	// Using this in a production application would create a major security
	// vulnerability, as it allows for man-in-the-middle attacks.
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	// Dial the server using the custom TLS configuration. We set a timeout
	// to prevent the program from hanging indefinitely.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	// Ensure the connection is closed when the function exits.
	defer conn.Close()

	// The ConnectionState contains details about the TLS connection,
	// including the certificates presented by the peer.
	state := conn.ConnectionState()

	// PeerCertificates is a slice of parsed X.509 certificates.
	// The first certificate in the slice is the leaf certificate, followed by
	// any intermediates provided by the server.
	return state.PeerCertificates, nil
}
