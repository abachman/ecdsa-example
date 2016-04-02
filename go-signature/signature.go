package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"runtime"
)

// generate and verify simple ECDSA signed documents

//// Document Handling

type SignedDocument struct {
	Cleartext   string `json:"cleartext"`
	Signature64 string `json:"signature"`
	Signature   []byte
}

func LoadDocument(docText []byte) (*SignedDocument, error) {
	document := &SignedDocument{}

	if err := json.Unmarshal(docText, &document); err != nil {
		return nil, err
	}

	sig, err := base64.StdEncoding.DecodeString(document.Signature64)
	if err != nil {
		return nil, err
	}
	document.Signature = sig

	return document, nil
}

//// Key Handling

// LoadPublicKey a helper method for setting qlablicense's global public key var from the given string
func LoadPublicKey(pemText []byte) interface{} {
	// decode key from .pem format
	block, _ := pem.Decode(pemText)

	if block == nil {
		log.Println("error loading key")
		return nil
	}

	// parse key from decoded .pem block
	key, err := x509.ParsePKIXPublicKey(block.Bytes) // (pub interface{}, err error)
	if err != nil {
		log.Println("error parsing pem.", err)
		return nil
	}

	// type convert to *rsa.PublicKey
	if k, ok := key.(*rsa.PublicKey); ok {
		return k
	} else if k, ok := key.(*ecdsa.PublicKey); ok {
		return k
	}

	log.Println("error, public key is of unknown type")
	return nil
}

//// Verification

func VerifyRSA(key *rsa.PublicKey, doc *SignedDocument) (bool, error) {
	hashed := sha256.Sum256([]byte(doc.Cleartext))
	err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed[:], doc.Signature)
	if err != nil {
		return false, err
	}
	return true, nil
}

func VerifyECDSA(key *ecdsa.PublicKey, doc *SignedDocument) (bool, error) {
	// ECDSA signatures usually provide a pair of numbers in the signature
	// called r and s. The most common way to serialise these two numbers is
	// using ASN.1 as defined in [SEC1], and we’ll use this when signing with
	// ECDSA.
	// - https://leanpub.com/gocrypto/read#leanpub-auto-ecdsa
	type ECDSASignature struct {
		R, S *big.Int
	}

	unmarshalResult := make(chan ECDSASignature)
	unmarshalError := make(chan error)

	go func() {
		var rs ECDSASignature

		// If we pass unexpected signature values in (e.g., RSA sig with ECDSA verification) asn1.Unmarshal can panic
		if _, err := asn1.Unmarshal(doc.Signature, &rs); err != nil {
			unmarshalError <- fmt.Errorf("failed to unmarshal ECDSA license signature")
		}

		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(runtime.Error); ok {
					panic(r)
				}
				unmarshalError <- fmt.Errorf("failed to unmarshal ECDSA license signature")
			}
		}()

		unmarshalResult <- rs
	}()

	var rs ECDSASignature
	var err error
	select {
	case rs = <-unmarshalResult:
		// got result
	case err = <-unmarshalError:
		// got error
	}

	if err != nil {
		log.Println("unable to unmarshal ECDSA license signature")
		return false, err
	}

	if rs.R == nil || rs.S == nil {
		log.Println("unable to unmarshal ECDSA license signature")
		return false, fmt.Errorf("license verification failed")
	}

	hashed := sha256.Sum256([]byte(doc.Cleartext))
	sigOk := ecdsa.Verify(key, hashed[:], rs.R, rs.S)

	if sigOk {
		return true, nil
	} else {
		log.Println("ECDSA verification failed")
		return false, fmt.Errorf("license verification failed")
	}
}

func VerifyDocument(key interface{}, doc *SignedDocument) (bool, error) {
	var (
		rKey *rsa.PublicKey
		eKey *ecdsa.PublicKey
	)

	switch key.(type) {
	case *rsa.PublicKey:
		rKey, _ = key.(*rsa.PublicKey)
	case *ecdsa.PublicKey:
		eKey, _ = key.(*ecdsa.PublicKey)
	}

	if rKey != nil {
		log.Println("use rsa signature verification")
		return VerifyRSA(rKey, doc)
	} else if eKey != nil {
		return VerifyECDSA(eKey, doc)
	}

	return false, fmt.Errorf("key was not a recognized type")
}

func main() {
	//// FLAGS
	var (
		documentPath = flag.String("document", "document.json", "document.json path")
		keyPath      = flag.String("key", "public_key.ecdsa.pem", "verification key path")
	)
	flag.Parse()

	// read in and load key
	keyText, err := ioutil.ReadFile(*keyPath)
	if err != nil {
		log.Println("error reading key file.", err)
		panic(err)
	}

	key := LoadPublicKey(keyText)
	if key == nil {
		panic(fmt.Errorf("failed to load key"))
	}

	// read in and load document
	docText, err := ioutil.ReadFile(*documentPath)
	if err != nil {
		log.Println("error reading key file.", err)
		panic(err)
	}

	document, err := LoadDocument(docText)
	if err != nil {
		log.Println("error parsing document", err)
		panic(err)
	}

	// verify!
	result, err := VerifyDocument(key, document)
	if err != nil {
		log.Println("verification failed!", err)
		panic(err)
	}

	if result {
		fmt.Println("ok")
	} else {
		fmt.Println("failed")
	}
}
