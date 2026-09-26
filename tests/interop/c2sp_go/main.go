// Generates and checks C2SP signed-note / tlog-cosignature vectors with the Go
// reference packages, for calybris-core's checkpoint module.
//
//	go run . gen > ../../fixtures/c2sp_go_vectors.json   # new vectors
//	go run . verify NOTE                                 # check a note signed with the vector keys
//
// The cosignature timestamp is the time of the run, so regenerated vectors
// differ in that line only; tests/c2sp_interop.rs accepts any time.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"

	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/formats/log"
	"golang.org/x/mod/sumdb/note"
)

func keyHash(name string, alg byte, pub []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name + "\n"))
	h.Write([]byte{alg})
	h.Write(pub)
	return binary.BigEndian.Uint32(h.Sum(nil))
}

func keys(name string, alg byte, seed []byte) (string, string) {
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	h := keyHash(name, alg, pub)
	sk := fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", name, h, base64.StdEncoding.EncodeToString(append([]byte{alg}, seed...)))
	vk := fmt.Sprintf("%s+%08x+%s", name, h, base64.StdEncoding.EncodeToString(append([]byte{alg}, pub...)))
	return sk, vk
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rep(b byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = b
	}
	return s
}

func main() {
	logSK, logVK := keys("calybris.example/interop", 1, rep(0x11))
	witSK, witVK := keys("witness.example", 4, rep(0x22))
	switch os.Args[1] {
	case "gen":
		// Go's own verifier-key constructor must agree with ours.
		pub := ed25519.NewKeyFromSeed(rep(0x11)).Public().(ed25519.PublicKey)
		goVK, err := note.NewEd25519VerifierKey("calybris.example/interop", pub)
		must(err)
		if goVK != logVK {
			must(fmt.Errorf("vkey mismatch %s %s", goVK, logVK))
		}
		ls, err := note.NewSigner(logSK)
		must(err)
		ws, err := fnote.NewSignerForCosignatureV1(witSK)
		must(err)
		root := sha256.Sum256([]byte("calybris interop root"))
		body := fmt.Sprintf("calybris.example/interop\n5\n%s\nprev deadbeef\n", base64.StdEncoding.EncodeToString(root[:]))
		signed, err := note.Sign(&note.Note{Text: body}, ls, ws)
		must(err)
		out, _ := json.MarshalIndent(map[string]string{
			"log_skey": logSK, "log_vkey": logVK,
			"witness_skey": witSK, "witness_vkey": witVK,
			"note": string(signed),
		}, "", "  ")
		fmt.Println(string(out))
	case "verify":
		raw, err := os.ReadFile(os.Args[2])
		must(err)
		lv, err := note.NewVerifier(logVK)
		must(err)
		wv, err := fnote.NewVerifierForCosignatureV1(witVK)
		must(err)
		n, err := note.Open(raw, note.VerifierList(lv, wv))
		must(err)
		var cp log.Checkpoint
		_, err = cp.Unmarshal([]byte(n.Text))
		must(err)
		for _, s := range n.Sigs {
			fmt.Printf("verified %s\n", s.Name)
		}
		fmt.Printf("checkpoint %s size=%d\n", cp.Origin, cp.Size)
	}
}
