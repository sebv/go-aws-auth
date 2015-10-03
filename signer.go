package awsauth

type Signer interface {
	Keys() Credentials
	Sign4Signature(stringToSign string, meta *Metadata) string
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

func (s *signer) Sign4Signature(stringToSign string, meta *Metadata) string {
	signingKey := signingKeyV4(s.keys.SecretAccessKey, meta.Date, meta.Region, meta.Service)
	return signatureV4(signingKey, stringToSign)
}
