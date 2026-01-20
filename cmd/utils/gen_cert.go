package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {
	certOut := flag.String("cert", "tunnel-cert.pem", "output cert file")
	keyOut := flag.String("key", "tunnel-key.pem", "output key file")
	host := flag.String("cn", "localhost", "common name / host")
	days := flag.Int("days", 365, "valid days")
	flag.Parse()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}
	notBefore := time.Now().Add(-time.Hour)
	notAfter := notBefore.Add(time.Duration(*days) * 24 * time.Hour)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: *host,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("create cert: %v", err)
	}
	if err := writePem(*certOut, "CERTIFICATE", derBytes); err != nil {
		log.Fatalf("write cert: %v", err)
	}
	if err := writePem(*keyOut, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(priv)); err != nil {
		log.Fatalf("write key: %v", err)
	}
	log.Printf("generated self-signed cert=%s key=%s", *certOut, *keyOut)
}

func writePem(path, typ string, data []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: data})
}
