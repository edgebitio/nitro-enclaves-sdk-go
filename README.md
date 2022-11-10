# Nitro Enclaves SDK for Go

A pure Go library for utilizing AWS KMS's support for Nitro Enclaves, similar to the
[AWS Nitro Enclaves SDK for C](https://github.com/aws/aws-nitro-enclaves-sdk-c).

# Usage

In order to utilize KMS's support for Nitro Enclaves from Go, we must:

1. Obtain an attestation document from the enclave's Nitro Security Module
2. Attach that attestation document to a supported KMS call
3. Decode and decrypt the `CiphertextForRecipient` field of the response

## Pre-Requisites

By default, Nitro Enclaves do not provide network connectivity, or seed the
enclave kernel's entropy pool. To simplify the process of getting a working
enclave, we'll use [Enclaver](https://github.com/edgebitio/enclaver) to automate
building of Enclave Images.

First, if you don't have one already, create a Dockerfile to build your Go app
into a Docker image:

```Dockerfile
# Build Image Stage
FROM golang:1.18-alpine AS app-builder
WORKDIR /usr/src/go-enclave-app
COPY . .
RUN go build -v -o /usr/local/bin/go-enclave-app main.go

# Release Image Stage
FROM alpine:latest AS app-container

COPY --from=app-builder /usr/local/bin/go-enclave-app /usr/local/bin/go-enclave-app
CMD ["/usr/local/bin/go-enclave-app"]
```

Now you can build your app into a Docker image by running:

```sh
go build . -t go-enclave-app
```

Now create an Enclaver manifest called `enclaver.yaml` alongside your Dockerfile:

```yaml
version: v1
name: "go-enclave-app"
target: "go-enclave-app:enclave-latest"
sources:
  app: "go-enclave-app"
egress:
  allow:
    - 169.254.169.254
    - kms.us-west-2.amazonaws.com
```

This will instruct Enclaver to build a distributable Nitro Enclaves-enabled
Docker image tagged as `go-enclave-app:enclave-latest` from the source
`go-enclave-app` image, and cause Enclaver to permit egress traffic to the local
instance metadata service and the `us-west-2` KMS endpoint.

You can test this by running:

```sh
enclaver build
```

## Obtaining an Attestation Document

The heavy-lifting for obtaining an attestation document is done, behind-the-scenes, by [Nitro Security
Module Interface for Go)[https://github.com/hf/nsm].

In order for KMS to use NSM attestation documents, the attestation documents
must include a public key corresponding to a private key accessible by the
enclave. For simplicity, this library abstracts generation of the key and
interactions with the Nitro Security Module behind the `EnclaveHandle`
interface:

*Note: this private key should never leave the enclave - it is OK for it to be
ephemeral, and generate a new key for each enclave instance.*

First, add this library as a dependency:

```sh
go get github.com/edgebitio/nitro-enclaves-sdk-go@latest
```

Then, in your code, grab a reference to the global handle, and use it to request
an attestation document:

```go
import (
	enclave "github.com/edgebitio/nitro-enclaves-sdk-go"
)

func MakeKMSRequest() error {
	enclaveHandle, err := enclave.GetOrInitializeHandle()
	if err != nil {
		return err
	}

	attestationDocument, err := enclaveHandle.Attest(enclave.AttestationOptions{})
	if err != nil {
		return err
	}

    ...
}
```

## Making KMS Requests

Official AWS SDKs do not include support for Nitro Enclaves. They are also
extensive, and well-maintained, so forking or re-implementing them is not a good
option.

Instead, this library provides a drop-in replacement for
`github.com/aws/aws-sdk-go-v2/service/kms`, which can be used trasparently via
the Go Modules `replace` directive.

To do so, within your module run:

```sh
go mod edit -replace \
    github.com/aws/aws-sdk-go-v2/service/kms=github.com/edgebitio/nitro-enclaves-sdk-go/kms@latest
```

Depending on your configuration you likely need to run `go mod tidy` and
possibly `go mod vendor` after this.

Now you can instantiate the KMS client and use it to make requests,
with the option to include an attestation document on Decrypt, GenerateDataKey,
and GenerateRandom operations using the `Recipient` input field:

```go
	ctx := context.TODO()
	config, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-west-2"))
	if err != nil {
		return err
	}

	kmsClient := kms.NewFromConfig(config)

	// Request a 32 byte data key from KMS, for use in AES-256 operations.
	dataKeyRes, err := kmsClient.GenerateDataKey(context.Background(), &kms.GenerateDataKeyInput{
		KeyId:   "arn:aws:kms:us-west-2:xxxxxxxxxx:key/12345678-abcd-ef12-1234-abcdef123456",
		KeySpec: types.DataKeySpecAes256,
		Recipient: &types.RecipientInfoType{
			AttestationDocument:    attestationDocument,
			KeyEncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
		},
	})
	if err != nil {
		return err
	}
```

## Decoding and Decrypting KMS Responses

When you include a `Recipient` field on a Decrypt, GenerateDataKey, or
GenerateRandom KMS call, KMS returns a null `Plaintext` field, and instead
includes the plaintext data in an encrypted form in the `CiphertextForRecipient`
field.

The `EnclaveHandle` interface provides the ability to decrypt this field using
the private key it generated for the enclave:

```go
	if dataKeyRes.CiphertextForRecipient == nil {
		return fmt.Errorf("CiphertextForRecipient is nil")
	}

	key, err := enclaveHandle.DecryptKMSEnvelopedKey(dataKeyRes.CiphertextForRecipient)
	if err != nil {
		return err
	}

	fmt.Printf("key: %v", key)
```

Now you can use `key` to encrypt data! To persist the encrypted data, you'll need
to also persist the value of `CiphertextBlob`, which can be decrypted at any time
using KMS.

## Separation of Duties

Note that anyone with the ability to perform `Decrypt` calls using your KMS key
will be able to decrypt the data key in `CiphertextBlob`, so for this to be useful
you will likely want:

1. To use a KMS Key Policy to lock down access to the KMS key such that only
   authorized enclave images are permitted to perform `Decrypt` operations.
   See the [AWS docs](https://docs.aws.amazon.com/enclaves/latest/user/kms.html)
   for details.
2. To ensure that only trusted users have permission to modify the KMS key policy
   - ideally these would be a completely different set of users than those who
   have normal production access, so that Nitro Enclaves + KMS can be used to
   enforce separation of duties.