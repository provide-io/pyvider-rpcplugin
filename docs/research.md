Research

`go-plugin`

`server.go`:
296: Begins to build the tlsConfig
310: Begin the automatic mTLS logic.
316: Call `generateCert()` in `mtls.go`

`mtls.go`
20: `func generateCert() (cert []byte, privateKey []byte, err error)`
21: States that it is hard coded as elliptic.P521.