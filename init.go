package main

import (
	"flag"
	"time"

	"github.com/CSCE482QuantumCryptography/qs509"
)

var opensslPath *string
var opensslCNFPath *string
var src *string
var signingAlg *string
var kemAlg *string
var caCert *string
var caKey *string
var timeMap map[string][]time.Time

func init() {
	opensslPath = flag.String("openssl-path", "../../build/bin/openssl", "the path to openssl 3.3")
	opensslCNFPath = flag.String("openssl-cnf-path", "../../openssl/apps/openssl.cnf", "the path to openssl config")
	src = flag.String("src", "127.0.0.1:9080", "the path address being listened on")
	signingAlg = flag.String("sa", "DILITHIUM3", "the algorithm used to sign the client certificate")
	kemAlg = flag.String("ka", "Kyber512", "the algorithm used for generating shared secret")
	caCert = flag.String("ca", "../qs509/etc/crt/dilithium3_CA.crt", "the file location of the ca cert used to sign")
	caKey = flag.String("ca-key", "../qs509/etc/keys/dilithium3_CA.key", "the file location of the ca key used to sign")

	// Parse flags
	flag.Parse()

	timeMap = make(map[string][]time.Time)

	// Initialize qs509
	qs509.Init(*opensslPath, *opensslCNFPath)
}
