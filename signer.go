package awsauth

type Signer interface {
	Keys() Credentials
	SignatureV4(stringToSign string, meta *Metadata) string
}

type SimpleSigner struct {
	keys Credentials
}

func NewSimpleSigner(keys Credentials) Signer {
	ss := new(SimpleSigner)
	ss.keys = keys
	return ss
}

func (ss *SimpleSigner) Keys() Credentials {
	// the the secret id is hidden
	safeKeys := new(Credentials)
	safeKeys.AccessKeyID = ss.keys.AccessKeyID
	safeKeys.SecurityToken = ss.keys.SecurityToken
	safeKeys.Expiration = ss.keys.Expiration
	return *safeKeys
}

func (ss *SimpleSigner) SignatureV4(stringToSign string, meta *Metadata) string {
	signingKey := signingKeyV4(ss.keys.SecretAccessKey, meta.date, meta.region, meta.service)
	return signatureV4(signingKey, stringToSign)
}
