package awsauth

type Signer interface {
	Keys() Credentials
	SignatureV4(stringToSign string, meta *metadata) string
}

type signer struct {
	keys Credentials
}

func NewSigner(keys Credentials) Signer {
	s := new(signer)
	s.keys = keys
	return s
}

func (s *signer) Keys() Credentials {
	// the the secret id is hidden
	safeKeys := new(Credentials)
	safeKeys.AccessKeyID = s.keys.AccessKeyID
	safeKeys.SecurityToken = s.keys.SecurityToken
	safeKeys.Expiration = s.keys.Expiration
	return *safeKeys
}

func (s *signer) SignatureV4(stringToSign string, meta *metadata) string {
	signingKey := signingKeyV4(s.keys.SecretAccessKey, meta.date, meta.region, meta.service)
	return signatureV4(signingKey, stringToSign)
}
