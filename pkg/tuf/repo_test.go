// Copyright 2022 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tuf

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"

	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf"
	"knative.dev/pkg/logging"
)

const (
	fulcioRootCert = `-----BEGIN CERTIFICATE-----
MIICNzCCAd2gAwIBAgITPLBoBQhl1hqFND9S+SGWbfzaRTAKBggqhkjOPQQDAjBo
MQswCQYDVQQGEwJVSzESMBAGA1UECBMJV2lsdHNoaXJlMRMwEQYDVQQHEwpDaGlw
cGVuaGFtMQ8wDQYDVQQKEwZSZWRIYXQxDDAKBgNVBAsTA0NUTzERMA8GA1UEAxMI
dGVzdGNlcnQwHhcNMjEwMzEyMjMyNDQ5WhcNMzEwMjI4MjMyNDQ5WjBoMQswCQYD
VQQGEwJVSzESMBAGA1UECBMJV2lsdHNoaXJlMRMwEQYDVQQHEwpDaGlwcGVuaGFt
MQ8wDQYDVQQKEwZSZWRIYXQxDDAKBgNVBAsTA0NUTzERMA8GA1UEAxMIdGVzdGNl
cnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQRn+Alyof6xP3GQClSwgV0NFuY
YEwmKP/WLWr/LwB6LUYzt5v49RlqG83KuaJSpeOj7G7MVABdpIZYWwqAiZV3o2Yw
ZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQU
T8Jwm6JuVb0dsiuHUROiHOOVHVkwHwYDVR0jBBgwFoAUT8Jwm6JuVb0dsiuHUROi
HOOVHVkwCgYIKoZIzj0EAwIDSAAwRQIhAJkNZmP6sKA+8EebRXFkBa9DPjacBpTc
OljJotvKidRhAiAuNrIazKEw2G4dw8x1z6EYk9G+7fJP5m93bjm/JfMBtA==
-----END CERTIFICATE-----`

	ctlogPublicKey = `-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEAu1Ah4n2P8JGt92Qg86FdR8f1pou43yndggMuRCX0JB+bLn1rUFRA
KQVd+xnnd4PXJLLdml8ZohCr0lhBuMxZ7zBzt0T98kblUCxBgABPNpWIkTgacyC8
MlIYY/yBSuDWAJOA5IKi4Hh9nI+Mmb/FXgbOz5a5mZx8w7pMiTMu0+Rd9cPzRkUZ
DQfZsLONr6PwmyCAIL1oK80fevxKZPME0UV8bFPWnRxeVaFr5ddd/DOenV8H6SPy
r4ODbSOItpl53y6Az0m3FTIUf8cSsyR7dfE4zpA3M4djjtoKDNFRsTjU2RWVQW9X
MaxzznGVGhLEwkC+sYjR5NQvH5iiRvV18q+CGQqNX2+WWM3SPuty3nc86RBNR0FO
gSQA0TL2OAs6bJNmfzcwZxAKYbj7/88tj6qrjLaQtFTbBm2a7+TAQfs3UTiQi00z
EDYqeSj2WQvacNm1dWEAyx0QNLHiKGTn4TShGj8LUoGyjJ26Y6VPsotvCoj8jM0e
aN8Pc9/AYywVI+QktjaPZa7KGH3XJHJkTIQQRcUxOtDstKpcriAefDs8jjL5ju9t
5J3qEvgzmclNJKRnla4p3maM0vk+8cC7EXMV4P1zuCwr3akaHFJo5Y0aFhKsnHqT
c70LfiFo//8/QsvyjLIUtEWHTkGeuf4PpbYXr5qpJ6tWhG2MARxdeg8CAwEAAQ==
-----END RSA PUBLIC KEY-----`

	rekorPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEF6j2sTItLcs0wKoOpMzI+9lJmCzf
N6mY2prOeaBRV2dnsJzC94hOxkM5pSp9nbAK1TBOI45fOOPsH2rSR++HrA==
-----END PUBLIC KEY-----`

	// validRepository is a valid tar/gzipped repository representing an air-gap
	// TUF repository.
	validRepository = `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`

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

func TestCompressUncompressFS(t *testing.T) {
	files := map[string][]byte{
		"fulcio_v1.crt.pem": []byte(fulcioRootCert),
		"ctfe.pub":          []byte(ctlogPublicKey),
		"rekor.pub":         []byte(rekorPublicKey),
	}
	repo, dir, err := createRepo(context.Background(), files)
	if err != nil {
		t.Fatalf("Failed to CreateRepo: %s", err)
	}
	defer os.RemoveAll(dir)

	var buf bytes.Buffer
	fsys := os.DirFS(dir)
	if err = CompressFS(fsys, &buf, map[string]bool{"keys": true, "staged": true}); err != nil {
		t.Fatalf("Failed to compress: %v", err)
	}
	os.WriteFile("/tmp/newcompressed", buf.Bytes(), os.ModePerm)
	dstDir := t.TempDir()
	if err = Uncompress(&buf, dstDir); err != nil {
		t.Fatalf("Failed to uncompress: %v", err)
	}
	// Then check that files have been uncompressed there.
	meta, err := repo.GetMeta()
	if err != nil {
		t.Errorf("Failed to GetMeta: %s", err)
	}
	root := meta["root.json"]

	// This should have roundtripped to the new directory.
	rtRoot, err := os.ReadFile(filepath.Join(dstDir, "repository", "root.json"))
	if err != nil {
		t.Errorf("Failed to read the roundtripped root %v", err)
	}
	if !bytes.Equal(root, rtRoot) {
		t.Errorf("Roundtripped root differs:\n%s\n%s", string(root), string(rtRoot))
	}

	// As well as, say rekor.pub under targets dir
	rtRekor, err := os.ReadFile(filepath.Join(dstDir, "repository", "targets", "rekor.pub"))
	if err != nil {
		t.Errorf("Failed to read the roundtripped rekor %v", err)
	}
	if !bytes.Equal(files["rekor.pub"], rtRekor) {
		t.Errorf("Roundtripped rekor differs:\n%s\n%s", rekorPublicKey, string(rtRekor))
	}
}

func createRepo(ctx context.Context, files map[string][]byte) (tuf.LocalStore, string, error) {
	// TODO: Make this an in-memory fileystem.
	//	tmpDir := os.TempDir()
	//	dir := tmpDir + "tuf"
	dir := "/tmp/tuf"
	err := os.Mkdir(dir, os.ModePerm)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create tmp TUF dir: %w", err)
	}
	dir += "/"
	logging.FromContext(ctx).Infof("Creating the FS in %q", dir)
	local := tuf.FileSystemStore(dir, nil)

	// Create and commit a new TUF repo with the targets to the store.
	logging.FromContext(ctx).Infof("Creating new repo in %q", dir)
	r, err := tuf.NewRepoIndent(local, "", " ")
	if err != nil {
		return nil, "", fmt.Errorf("failed to NewRepoIndent: %w", err)
	}

	// Added by vaikas
	if err := r.Init(false); err != nil {
		return nil, "", fmt.Errorf("failed to Init repo: %w", err)
	}

	// Make all metadata files expire in 6 months.
	expires := time.Now().AddDate(0, 6, 0)

	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		_, err := r.GenKeyWithExpires(role, expires)
		if err != nil {
			return nil, "", fmt.Errorf("failed to GenKeyWithExpires: %w", err)
		}
	}

	targets := make([]string, 0, len(files))
	for k, v := range files {
		logging.FromContext(ctx).Infof("Adding %s file", k)
		if err := writeStagedTarget(dir, k, v); err != nil {
			return nil, "", fmt.Errorf("failed to write staged target %s: %w", k, err)
		}
		targets = append(targets, k)
	}
	err = r.AddTargetsWithExpires(targets, nil, expires)
	if err != nil {
		return nil, "", fmt.Errorf("failed to add AddTargetsWithExpires: %w", err)
	}

	// Snapshot, Timestamp, and Publish the repository.
	if err := r.SnapshotWithExpires(expires); err != nil {
		return nil, "", fmt.Errorf("failed to add SnapShotWithExpires: %w", err)
	}
	if err := r.TimestampWithExpires(expires); err != nil {
		return nil, "", fmt.Errorf("failed to add TimestampWithExpires: %w", err)
	}
	if err := r.Commit(); err != nil {
		return nil, "", fmt.Errorf("failed to Commit: %w", err)
	}
	return local, dir, nil
}

func writeStagedTarget(dir, path string, data []byte) error {
	path = filepath.Join(dir, "staged", "targets", path)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func TestClientFromSerializedMirror(t *testing.T) {
	repo, err := base64.StdEncoding.DecodeString(validRepository)
	if err != nil {
		t.Fatalf("failed to decode validrepository: %v", err)
	}
	root, err := base64.StdEncoding.DecodeString(rootJSON)
	if err != nil {
		t.Fatalf("failed to decode rootJSON: %v", err)
	}
	tufClient, err := ClientFromSerializedMirror(context.Background(), repo, root, "targets", "/repository/")
	if err != nil {
		t.Fatalf("Failed to unserialize repo: %v", err)
	}
	targets, err := tufClient.Targets()
	if err != nil {
		t.Errorf("failed to get Targets from tuf: %v", err)
	}
	if len(targets) == 0 {
		t.Errorf("Got no targets from the TUF client")
	}
}

func TestClientFromRemoteMirror(t *testing.T) {
	files := map[string][]byte{
		"fulcio_v1.crt.pem": []byte(fulcioRootCert),
		"ctfe.pub":          []byte(ctlogPublicKey),
		"rekor.pub":         []byte(rekorPublicKey),
	}
	local, dir, err := createRepo(context.Background(), files)
	if err != nil {
		t.Fatalf("Failed to CreateRepo: %s", err)
	}
	defer os.RemoveAll(dir)
	meta, err := local.GetMeta()
	if err != nil {
		t.Fatalf("getting meta: %v", err)
	}
	rootJSON, ok := meta["root.json"]
	if !ok {
		t.Fatalf("Getting root: %v", err)
	}
	serveDir := filepath.Join(dir, "repository")
	t.Logf("tuf repository was created in: %s serving tuf root at %s", dir, serveDir)
	fs := http.FileServer(http.Dir(serveDir))
	http.Handle("/", fs)

	ts := httptest.NewServer(fs)
	defer ts.Close()

	tufClient, err := ClientFromRemote(context.Background(), ts.URL, rootJSON, "targets")
	if err != nil {
		t.Fatalf("Failed to get client from remote: %v", err)
	}
	targets, err := tufClient.Targets()
	if err != nil {
		t.Errorf("failed to get Targets from tuf: %v", err)
	}
	if len(targets) == 0 {
		t.Errorf("Got no targets from the TUF client")
	}
}
