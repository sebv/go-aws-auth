package awsauth

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestSigner(t *testing.T) {
	// http://docs.aws.amazon.com/AmazonS3/2006-03-01/dev/RESTAuthentication.html
	// Note: S3 now supports signed signature version 4
	// (but signed URL requests still utilize a lot of the same functionality)

	Convey("Given a Signer", t, func() {
		var keys Credentials
		keys = *testCredV4
		signer := NewSigner(keys)

		Convey("It should not expose the secret access key", func() {
			safeKeys := signer.Keys()
			So(safeKeys.SecretAccessKey, ShouldBeBlank)
		})

		Convey("It should sign a string using the V4 algorithm", func() {
			meta := &Metadata{
				algorithm:       "AWS4-HMAC-SHA256",
				credentialScope: "20110909/us-east-1/iam/aws4_request",
				signedHeaders:   "content-type;host;x-amz-date",
			}
			signature := signer.Sign4Signature("aaa", meta)
			So(signature, ShouldEqual, "866b425ab5ba7edbd48997150e88273762008b785969828a88e4d282f9233909")
		})

	})
}
