// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1alpha1

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/sigstore/policy-controller/test"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"knative.dev/pkg/apis"
)

// validRepository is a TUF repository that's been tarred, gzipped and base64
// encoded. These are vars because conversion to []byte seems to make them not
// constant
var (
	validRepository = `H4sIAAAAAAAA/+xbW1MiyfKfZz6F4av/HTLrXhOxD92AioqKIq7+48REXQFFQRoG5cR+9xONd2dGZ1eHmd3pX4Q2dDVdWZlZmVmVWaMwHGS98WB09e67AQBAcn59FddXIOz6eo13yJECoQwZfwdIUeK7Jf79SLrHJBub0TuAXjZ49rlsbGJ8pv12ILfXfwju5V/G96PBYPz+JBucv20fOT8EY1+TPyMgnsifEyHfLS2Eib+4/P9bWlrOep3z4Jc/LP23tLS0/HF8NQzLH5aWc21Y/r/8VjYM7uOnMMp6g/O8Bd/DdcP9PZx/D5fD3ihk+TMEiPgN5G8ILSAfUH0gegX0B7j55Wm4ym56XFpGF1BZIX0gXHlFiQsEUAdnZQDhXESgXEflMZoYAgTDYmDoCRXMh8hvXzR/7S35wRPOUc+7y8fguuHsSw2n4arnP3ZN1v1o+p3BqDfunuWk/f+8eWk56xrCxc3T868cyfL823/uX/HJ9O+oWFoeTmy/5+Zs8IJJHVwwwcogDBhF8rE5zxwwFZUFIamT1Ft0aF2wQnhlKHDtjaXmuqM/8/9/zntb1p54oim1kjpuo6CM80DQGh1l0JwoDwQgBGs4kWCYASJsZMRIJkJE+xMzK0prPSeRBkUMU4ZQbTjKaJXjSpuACJErY5yM1hhqDA3AuKdShSBYhM+ZZYSI0WggQSnJJXDqpVZeqsANRMI1KBekDNoFL5mNAIRYtAoJ9cgV+4mZ5SOLHFESJ5XmVAvPKFdgiAWtmPAOWM4b4IwKJzgJ1lqCHhWnHqX+ArOiFNZHITxaimT+G++ZpUFpRIXcR8acDYpgcEA0UV6gjdxCdM5xjD8xs4AAi4Eo5HNV0AqkVBAY4ch8tIIKHwzX4ECCYAGocdwqK5D64Ak8moalG4Ytjwb9cG/E5ubyIQd6/iH9r7Zxj4Y67o5C1h30c6uND0SYnZth1n2WkFdPiW8iZGxGnTDOnqHj1dr2bXT0zkI2NmfDZyh5tUV9gZI7hXGD86yXjcP5+OMDQY1Hk1CaPzH3xGY8uXahOXnXqjWneO54X6tEN1rS6+Rvs2CUZDyCkwhWUnRGRJY/GSwDLqlSDJSOSnij0aJBiNFyLQKKYLxTaINiEbngRBoRI4MgXC4xFw1joCWEKBwHrRTlRloulCGee0GscTBX6T9LS/8p/fmjo6BfF4/i/1ulfOM1wAvxPyKXT+J/kV+K+H8BeCb+vzNR32sNcBbG5s593jiMuerd2+p+OO+Mu/m7qYQbA5vHCPd+9z4WyIkiMTdzXorc9gUaPGMQJUYOARFl8EJyFr2gVPIYAwUSgwAVaAQEob3yLnd5IkomudFeoULhIhIX86BTECODkz4iyRsYI4SA0sYYroNk8iZMuCH0AWfu/MA3GvpXO+lHhj4aQqJkNArmgRAW0XIf0XFniQhEog3WBB1sBBVtdFyKSKJiKIyMUZPAKHKmEIPylKBWQKO1PqBHa712UUXCGNOOKM8xOlAgHTUSvWc6AikM/U+LR/b/4Rx8wz5esP+EU/J0/0fywv4vBM/Y/9sQ/nuZ/ydLhGU3juH9MJx9yfpL9Q3G32MQYJXhNjLFpDKMKmsQQ1BB2MCko9pYpamRFDk4ooWSFqjBiJRLEz1zVkcPJCDxRmEwzlmCTgdNUcVgUCqPgghQgoWgDDMWRQSIgmnx2Pi7STYenD0ktNfJxoNRuL+1tDzJTGfO60prtXa7tl1azsZmPJmzMHHj3qdw3zIZ9fLb111dr0cfL+EnfdcbfIWLWn8DFx3RHCyJWkbGrfZMSiuklYoowSEwR23AENEZEDRynq+owQnwXOgYUBklJMGAILj3NliMgEiokxqdM5oSSQ2I4JgLKL0kXKHmAqVVGg3q+Bours5H/xZ8HIXTweg1yhiIc5p6JwOhnintpTQCJNfKROOREEoYUu/RO2kRpVKMMiqN8SZqg1EFAhQciYA0ItPIrfXInQpWKR+MZxSJjkEzxoP3zgTmA3eOImPAHX8NG/fywb+Oi38h1Hn1PsCjUMcoYb1mGo33PEL0zHNu0DEN3mNg+RsNsV6iUJw7iTQS6bQVTMfIQvCOeh+NoNY5Al5KyaQNIUpgPiqjBbfaCEq5QYwyOm4dIvUyoKecA/zTQp0H/v87ZX/+Vv4HKRT+fxEo8j9F/uenYVaR/ynyP0X+p8j/FPmfIv9TYCF4EP9/p+zP38r/AIgi/l8EivxPkf8p8j+/Lh7Y/5sZ+PZ9/PX6byYYKeq/F4HP5V/eNZfrwfgwyt5D+S2SKk9Z8+QKhIlHugCEU5Tvli4XwYBb+S+ir58QKMTS0Iy7v39BEX50Qu39bUaw9KO59O/FIsT+QvwPRDzJ/1NAYEX8vwj8liOtrdW3l3YP0q16ZWmzdjS/WWqsnk5r06P1zcFxfXYClaR5VL/5XE2artrsJLWdfuUAJqvNbHDc4umq6FQa461ZX5xN93dK5aPRrHler3d38dNK83hwOJONjaP9zZ649KZsau11u5keWZh0aynZavvLabY3OTu2zebvv5fmNNS2q5+R9aM59u/CS/7/LcoBXvT/HJ76f0Re+P9FAIX6qv//0aUg7++rWYpZ/52wCLG/tP8n2ZP8P5GCFPt/C8ED/1+p7bXqq/VK0qrdBAD1errbqqR8M6kmnVol/2skg7VK5WJtv8F0mjQqjQQuK7NkI+1st9Ok0UrOtruNlP1RbdVJqVGtTXdaNdpoda522oM/qq0GeXJvWp3VthtJtpbgQS25bNTsWrt7fJIeN9LGWim9uu4p6dTuek2mtfUE6kmaeLOim/XW1c7m/kazPewdds6HB+6sXVkZ7vT2ZqO1nVJ7sz2tdyH222Jz4/zI1PxGtafWJuH48Opsdwzlw54+6ZQPV6endpXtkdmOOWnMkstGwnKKfKk6raXlabOWTOtr02oS83Gu7zdqa9XksJPuV5yur50OaBNCzLJkj+ylW6diw48ms2Qz7XQuSt3Tk53dZrOadLbrSTVdTXrJZOciubicHDbW5EEV42A4O6pd+q2tLZkMD0BkJ0NzubF7nlWgWe+Wkt216bB8dZw1sTW4amTjrTDYGLJT5lT/k1txrQvgG3b/ssxlvI+aPhPmS4Len1VSZe4Enb69oFu1rUZyeivoyhGpTQ9bSSvtuFsu1dOcZdefG2k63a4kScuH053T0257RspX3f7aqohr1bWqWclG642zi+0J3dZ7Wak8Cj27xZPL1fO15vEG3+Ebgnf6Zxvr2cXW8cknezjbdGaCl00aTuGQDaA+bVaTnbk8myotJVHV8nEmnea0Oj2qtveglTTXy2lyME1yJZgl/vphVlvtNA8657v76XBzG7bXz+VWUiv50+Y+3+n9YWQ2rXTuQuVcc6r7zWS616l3k41p5maT3ZPjXXPM+uu1ybbfcO3NtM0+lXxsbjZOy8dtOdsp2xWV9GpJ37W2Lkw4i6tN0qjTfjdcbG/vbmxfyX26uXPY3mKiK873L9N27fdnhP/1+f9S/PcWdYwv7//Ip/EfAyjiv0UAhfxq/Peja1jf31XhFuHf98IixP6X93+IFLzY/1kIXrn/41ddv9nfLWdXR2ety8nWBa7iesdXpttel1Lm+8NOtTcLCU8H4+ZFr14+YtWDk+bK9slKu9oManByuHqmJ4cq6dONdNrLVsvn/T+mxf7PovD5/H/7EvAX5v+Xzn8JLNZ/C0Fx/qs4/1Wc/yrOfxXnv3758193pdILPv+NKJ7W/whkRfy/EDzn/+9K5xdSAPqo/PgLZlcQ+g0xAJOSBNDca6Ko9tIJEZQm0sfgpPRMEG5ARck1RiZiJIxz45h2JkrUlqHyViqgMThKfPSMAAlagHQkCME8x0iFY0hQsYhGenCGcW0Y8xK5fbMC0FefSXhkFTUl1oNiSqAOkThPgzbKSGU1E6C0oAwNIdKBC1Fqx3lkMhrUHBVTqKRS0jOCIkoNxnKvLQVvrZFcOWukMQaYVMAEDxosGkTtOFgAoj0D+k+zigUKFCjw78f/AgAA//8p3MEpAFwAAA==`

	// This is valid base64 (hello world), but should not be able to gunzip
	// untar.
	invalidRepository = []byte(`aGVsbG8gd29ybGQK`)

	// TUF Root json, generated via scaffolding
	// IMPORTANT: The next expiration is on '2026-07-09T17:18:29Z'
	// Steps to generate:
	// 1. cgit clone github.com/sigstore/scaffolding
	// 2. run ./hack/setup-kind.sh
	// 3. export KO_DOCKER_REPO=registry.local:5001/sigstore
	// 4. run ./hack/setup-scaffolding.sh
	// 5. get the secrets from the kind cluster
	//    kubectl get secrets -o yaml -n tuf-system tuf-root
	rootJSON = `ewogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgInNwZWNfdmVyc2lvbiI6ICIxLjAiLAogICJ2ZXJzaW9uIjogMSwKICAiZXhwaXJlcyI6ICIyMDI2LTA3LTEwVDAyOjE4OjI5KzA5OjAwIiwKICAia2V5cyI6IHsKICAgIjFjZTE4YjY3ZGUyNThkODMyY2UyMDE5ZWNiN2UwNmNjZjEwMzU5ZjhkMWZhZmVlMGVhNGZlNDFkMjM2NGRlZjUiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogIjJkNjQ3OWVjZWFlYjdlNmEwYTgyMjAxOWNkNGMwNDhmOGIwNjczYzczZGIxYzFiY2ViNjZkOGEzMDU5ZGFiM2EiCiAgICB9CiAgIH0sCiAgICI5ZDJkMjkzM2I3M2M1YmY2MzQ1NWUyMWJhOWY3ZTk1MjhkMDIwMGVlYmE1MjcwYTRhMDI2YmY0MmE3NDZlZjFiIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICJmN2JiZDUyZjNlODJhNDhhMjM5YTUxN2ZiOGM1ODlhZTExMGY1OGFhYzdmYmFhM2FhM2UwNDVkMzc4ZWU2NGYwIgogICAgfQogICB9LAogICAiYTY2ZmZhOTAyZTg4NzU3MDUzZDc5OGQ3OGU1YTBmMjU5MDhjZTc3ZTljZWQ3NGJmMDAyMmIxYjgxMjNkMTU4NCI6IHsKICAgICJrZXl0eXBlIjogImVkMjU1MTkiLAogICAgInNjaGVtZSI6ICJlZDI1NTE5IiwKICAgICJrZXlpZF9oYXNoX2FsZ29yaXRobXMiOiBbCiAgICAgInNoYTI1NiIsCiAgICAgInNoYTUxMiIKICAgIF0sCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiZGY0ZjUxMTcyYzc4OTUzOTZkNDM1ODBhMmIwOTg0NmRjMDQ0NWQzMDU0MzZjNjUyZWJiYjIxZDE4NTNkMTc5MCIKICAgIH0KICAgfSwKICAgImY3NmJkZjY2ZDFiMzEyYzY1MmVkZDRiM2U4OTExODE1ZGY0NGNiZTgyMWVjMDI5MjhkNjFiZjViMGZjY2M1MWYiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogIjAyMDRmZTI4MTUwMmU4ODk4MDc3ODBlNDI1MTRkZmI2MzZkZWE1OTBjMDcwNjRlMDNhYzViOGI2MTNkZWQyMGEiCiAgICB9CiAgIH0KICB9LAogICJyb2xlcyI6IHsKICAgInJvb3QiOiB7CiAgICAia2V5aWRzIjogWwogICAgICIxY2UxOGI2N2RlMjU4ZDgzMmNlMjAxOWVjYjdlMDZjY2YxMDM1OWY4ZDFmYWZlZTBlYTRmZTQxZDIzNjRkZWY1IgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJzbmFwc2hvdCI6IHsKICAgICJrZXlpZHMiOiBbCiAgICAgImE2NmZmYTkwMmU4ODc1NzA1M2Q3OThkNzhlNWEwZjI1OTA4Y2U3N2U5Y2VkNzRiZjAwMjJiMWI4MTIzZDE1ODQiCiAgICBdLAogICAgInRocmVzaG9sZCI6IDEKICAgfSwKICAgInRhcmdldHMiOiB7CiAgICAia2V5aWRzIjogWwogICAgICJmNzZiZGY2NmQxYjMxMmM2NTJlZGQ0YjNlODkxMTgxNWRmNDRjYmU4MjFlYzAyOTI4ZDYxYmY1YjBmY2NjNTFmIgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJ0aW1lc3RhbXAiOiB7CiAgICAia2V5aWRzIjogWwogICAgICI5ZDJkMjkzM2I3M2M1YmY2MzQ1NWUyMWJhOWY3ZTk1MjhkMDIwMGVlYmE1MjcwYTRhMDI2YmY0MmE3NDZlZjFiIgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0KICB9LAogICJjb25zaXN0ZW50X3NuYXBzaG90IjogdHJ1ZQogfSwKICJzaWduYXR1cmVzIjogWwogIHsKICAgImtleWlkIjogIjFjZTE4YjY3ZGUyNThkODMyY2UyMDE5ZWNiN2UwNmNjZjEwMzU5ZjhkMWZhZmVlMGVhNGZlNDFkMjM2NGRlZjUiLAogICAic2lnIjogImIwYTg3NDVmMGM3MTBiNzMxY2E2ZjQ2NGRlZWI0MDU3Mzg4NDA4OWY4NmRhOTFiMWExMGZmYjU5NmUxNmVhZGM4MWJlODRmMTU2NTI3YTZmZjQwZTZjZTgyMWNmYTQ0MDk3MGVmNmM1MDk4ODM1YTdiNTY4YTJkNWQ2MmJhYzA1IgogIH0KIF0KfQ==`
)

func TestTrustRootValidation(t *testing.T) {
	rootJSONDecoded, err := base64.StdEncoding.DecodeString(rootJSON)
	if err != nil {
		t.Fatalf("Failed to decode rootJSON for testing: %v", err)
	}
	validRepositoryDecoded, err := base64.StdEncoding.DecodeString(validRepository)
	if err != nil {
		t.Fatalf("Failed to decode validRepository for testing: %v", err)
	}
	tests := []struct {
		name        string
		trustroot   TrustRoot
		errorString string
	}{{
		name: "Should work with a valid repository",
		trustroot: TrustRoot{
			Spec: TrustRootSpec{
				Repository: &Repository{
					Root:     rootJSONDecoded,
					MirrorFS: validRepositoryDecoded,
					Targets:  "targets",
				},
			},
		},
	}, {
		name:        "Should fail with a missing repository.root",
		errorString: "missing field(s): spec.repository.root",
		trustroot: TrustRoot{
			Spec: TrustRootSpec{
				Repository: &Repository{
					MirrorFS: validRepositoryDecoded,
					Targets:  "targets",
				},
			},
		},
	}, {
		name:        "Should fail with a missing repository.repository",
		errorString: "missing field(s): spec.repository.repository",
		trustroot: TrustRoot{
			Spec: TrustRootSpec{
				Repository: &Repository{
					Root:    rootJSONDecoded,
					Targets: "targets",
				},
			},
		},
	}, {
		name:        "Should fail with a missing repository.targets",
		errorString: "missing field(s): spec.repository.targets",
		trustroot: TrustRoot{
			Spec: TrustRootSpec{
				Repository: &Repository{
					Root:     rootJSONDecoded,
					MirrorFS: validRepositoryDecoded,
				},
			},
		},
	}, {
		name:        "Should fail with an invalid repository.mirrorFS, not a gzip/tar file",
		errorString: "invalid value: failed to construct a TUF client: spec.repository.mirrorFS\nfailed to uncompress: gzip: invalid header",
		trustroot: TrustRoot{
			Spec: TrustRootSpec{
				Repository: &Repository{
					Root:     rootJSONDecoded,
					MirrorFS: invalidRepository,
					Targets:  "targets",
				},
			},
		},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.trustroot.Validate(context.TODO())
			validateError(t, test.errorString, "", err)
		})
	}
}

func TestTimeStampAuthorityValidation(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, _, _ := test.GenerateLeafCert("subject", "oidc-issuer", subCert, subKey)
	rootCert2, rootKey2, _ := test.GenerateRootCa()
	subCert2, subKey2, _ := test.GenerateSubordinateCa(rootCert2, rootKey2)
	leafCert2, _, _ := test.GenerateLeafCert("subject", "oidc-issuer", subCert2, subKey2)

	pem, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{rootCert, subCert, leafCert})
	if err != nil {
		t.Fatalf("unexpected error marshalling certificates to PEM: %v", err)
	}
	tooManyLeavesPem, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{rootCert, subCert, leafCert, leafCert2})
	if err != nil {
		t.Fatalf("unexpected error marshalling certificates to PEM: %v", err)
	}

	tests := []struct {
		name        string
		tsa         CertificateAuthority
		errorString string
	}{{
		name: "Should work with a valid repository",
		tsa: CertificateAuthority{
			Subject: DistinguishedName{
				Organization: "fulcio-organization",
				CommonName:   "fulcio-common-name",
			},
			URI:       *apis.HTTPS("fulcio.example.com"),
			CertChain: pem,
		},
	}, {
		name:        "Should fail splitting the certificates of the certChain",
		errorString: "invalid value: error splitting the certificates: certChain\nerror during PEM decoding",
		tsa: CertificateAuthority{
			Subject: DistinguishedName{
				Organization: "fulcio-organization",
				CommonName:   "fulcio-common-name",
			},
			URI:       *apis.HTTPS("fulcio.example.com"),
			CertChain: []byte("INVALID"),
		},
	}, {
		name:        "Should fail with a must contain at most one TSA certificate",
		errorString: "invalid value: certificate chain must contain at most one TSA certificate: certChain",
		tsa: CertificateAuthority{
			Subject: DistinguishedName{
				Organization: "fulcio-organization",
				CommonName:   "fulcio-common-name",
			},
			URI:       *apis.HTTPS("fulcio.example.com"),
			CertChain: tooManyLeavesPem,
		},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateTimeStampAuthority(context.TODO(), test.tsa)
			validateError(t, test.errorString, "", err)
		})
	}
}

func TestIgnoreStatusUpdatesTrustRoot(t *testing.T) {
	tr := &TrustRoot{Spec: TrustRootSpec{}}

	if err := tr.Validate(apis.WithinSubResourceUpdate(context.Background(), &tr, "status")); err != nil {
		t.Errorf("Failed to update status on invalid resource: %v", err)
	}
}
