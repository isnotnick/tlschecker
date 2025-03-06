package tlschecker

import (
	_ "bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	_ "io"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	_ "strconv"
	"strings"
	"time"

	"github.com/bogdanovich/dns_resolver"
	"github.com/domainr/dnsr"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

// Global regular expressions
var (
	reg             *regexp.Regexp
	timeoutSecs     time.Duration = 3 * time.Second
	timeoutDeadline time.Duration = 3 * time.Second
	connRetry       int           = 2
)

// Trust stores
var (
	mozStore   *x509.CertPool
	msStore    *x509.CertPool
	appleStore *x509.CertPool
)

// Trust store files
var (
	mozFile   string = "truststores/Mozilla-PEM-13112023.pem"
	msFile    string = "truststores/MS-PEM-13112023.pem"
	appleFile string = "truststores/Apple-PEM-13112023.pem"
)

func init() {
	//	Compile regular expressions for IP-address check and HTTP-Header server-token parsing
	reg = regexp.MustCompile("[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")

	//	Load the root stores from the PEM files
	mozCerts, _ := ioutil.ReadFile(mozFile)
	mozStore = x509.NewCertPool()
	mozStore.AppendCertsFromPEM(mozCerts)

	appleCerts, _ := ioutil.ReadFile(appleFile)
	appleStore = x509.NewCertPool()
	appleStore.AppendCertsFromPEM(appleCerts)

	msCerts, _ := ioutil.ReadFile(msFile)
	msStore = x509.NewCertPool()
	msStore.AppendCertsFromPEM(msCerts)
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
	AppleTrust string `json:"appletrust"`
	MozTrust   string `json:"moztrust"`
	MSTrust    string `json:"mstrust"`
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

	MozTrust   string
	MSTrust    string
	AppleTrust string

	CertificateOwner string

	ProductType string

	ErrorMessage string
}

func StoreSummaries() {
	fmt.Printf("Apple Root Store loaded from [%v] - number of certs : %v\n", appleFile, len(appleStore.Subjects()))
	fmt.Printf("Microsoft Root Store loaded from [%v] - number of certs : %v\n", msFile, len(msStore.Subjects()))
	fmt.Printf("Moz Root Store loaded from [%v] - number of certs : %v\n", mozFile, len(mozStore.Subjects()))
}

func CheckCertificate(address string) CertResult {
	// CertPool for the server-provided chain
	providedIntermediates := x509.NewCertPool()

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
	r := dnsr.New(10000)
	var caaRecords, mxRecords, nsRecords, ptrRecords strings.Builder
	for _, rr := range r.Resolve(thisCertificate.HostName, "CAA") {
		if rr.Type == "CAA" {
			caaRecords.WriteString(rr.Value + ",")
		}
	}
	for _, rr := range r.Resolve(thisCertificate.HostName, "MX") {
		if rr.Type == "MX" {
			mxRecords.WriteString(rr.Value + ",")
		}
	}
	for _, rr := range r.Resolve(thisCertificate.HostName, "NS") {
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

	//	New version of TLS connection and HTTP request
	//
	// Disable normal certificate validation checking, attempt TLS connection to host - also use 'servername' to support SNI
	//	Ordering of ciphersuites set here (rather than Go defaults) in an effort to seem more 'browserlike'
	tlsConfig := tls.Config{
		ServerName:         domainName,
		InsecureSkipVerify: true,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}
	var conn *tls.Conn
	var err error

	tr := &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			conn, err = tls.Dial("tcp", finalConnection, &tlsConfig)
			return conn, err
		},
		TLSHandshakeTimeout:   2 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	client := &http.Client{Transport: tr}
	response, err := client.Get("https://" + domainName + "/")

	if err != nil {
		thisCertificate.ErrorMessage = "Failed TCP connection / Connection refused"
		return thisCertificate
	}

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

	//	Log the OCSP response (in base64) if we are given one
	if len(conn.OCSPResponse()) != 0 {
		thisCertificate.OCSPStaple = base64.StdEncoding.EncodeToString(conn.OCSPResponse())
	}

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
