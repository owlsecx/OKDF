// ============================================================
//
//	OKDF — Key-Derivation Playground (PBKDF2 / HKDF)
//	Author  : khaled.s.haddad
//	Website : owlsec.org
//	Language: Go (stdlib only, CGO disabled, static build) — OWL suite
//
//	PBKDF2 (RFC 2898) and HKDF (RFC 5869) implemented from scratch
//	on crypto/hmac and the SHA-2 family. Derive keys, verify
//	password hashes in constant time, calibrate iteration cost,
//	and document the memory-hard KDFs (scrypt/Argon2id/bcrypt)
//	that live outside the standard library.
//
// ============================================================
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"os"
	"strconv"
	"strings"
	"time"
)

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
const (
	R   = "\033[91m"
	GRN = "\033[92m"
	YLW = "\033[93m"
	CY  = "\033[96m"
	W   = "\033[97m"
	B   = "\033[1m"
	X   = "\033[0m"
	MG  = "\033[95m"
	DIM = "\033[2m"
	OR  = "\033[38;5;208m"
	GY  = "\033[90m"
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear() {
	if !noColor {
		fmt.Print("\033[H\033[2J")
	}
}
func rule()            { fmt.Println(col(strings.Repeat("─", 66), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }

func header(title string) {
	fmt.Println()
	rule()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	rule()
	fmt.Println()
}

var stdin = bufio.NewReader(os.Stdin)

func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, err := stdin.ReadString('\n')
	if err != nil && s == "" {
		fmt.Println()
		os.Exit(0)
	}
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	stdin.ReadString('\n')
}

func stripANSI(s string) string {
	out := []rune{}
	esc := false
	for _, r := range s {
		if r == '\033' {
			esc = true
			continue
		}
		if esc {
			if r == 'm' {
				esc = false
			}
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
func visw(s string) int { return len([]rune(stripANSI(s))) }
func pad(s string, n int) string {
	if visw(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-visw(s))
}
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = visw(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && visw(c) > w[i] {
				w[i] = visw(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), B+CY))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", DIM))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), DIM))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", DIM))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

const BANNER = `
 ██████╗ ██╗  ██╗██████╗ ███████╗
██╔═══██╗██║ ██╔╝██╔══██╗██╔════╝
██║   ██║█████╔╝ ██║  ██║█████╗  
██║   ██║██╔═██╗ ██║  ██║██╔══╝  
╚██████╔╝██║  ██╗██████╔╝██║     
 ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝     
`

const (
	APPNAME = "OKDF"
	SUITE   = "Owl Crypto Suite"
	TAGLINE = "PBKDF2 · HKDF Key-Derivation Playground"
	SUBLINE = "PBKDF2 · HKDF · Verify · Cost calibration · Storage strings · Reference"
	VERSION = "1.0"
	AUTHOR  = "khaled.s.haddad"
	WEBSITE = "owlsec.org"
)

func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	rule()
	fmt.Println()
}

// ---------------------------------------------------------------------------
// Core KDFs (stdlib only)
//
// PBKDF2 and HKDF are implemented from scratch on crypto/hmac and the SHA-2
// family (RFC 2898 / RFC 5869). scrypt, Argon2id and bcrypt are NOT part of the
// Go standard library (golang.org/x/crypto). To stay a single stdlib-only
// static binary this tool does NOT import them; the reference screen documents
// the exact parameters you would use with those memory-hard KDFs.
// ---------------------------------------------------------------------------

// pbkdf2 — RFC 2898 PBKDF2 using an HMAC PRF.
func pbkdf2(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hLen := prf.Size()
	numBlocks := (keyLen + hLen - 1) / hLen
	dk := make([]byte, 0, numBlocks*hLen)
	buf := make([]byte, 4)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf)
		u := prf.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for i := range t {
				t[i] ^= u[i]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// hkdfExtract — RFC 5869 extract step.
func hkdfExtract(salt, ikm []byte, h func() hash.Hash) []byte {
	if len(salt) == 0 {
		salt = make([]byte, h().Size())
	}
	m := hmac.New(h, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

// hkdfExpand — RFC 5869 expand step.
func hkdfExpand(prk, info []byte, length int, h func() hash.Hash) ([]byte, error) {
	hLen := h().Size()
	if length > 255*hLen {
		return nil, fmt.Errorf("requested length too large (max %d)", 255*hLen)
	}
	var okm, t []byte
	for i := 1; len(okm) < length; i++ {
		m := hmac.New(h, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{byte(i)})
		t = m.Sum(nil)
		okm = append(okm, t...)
	}
	return okm[:length], nil
}

func hashByName(n string) (func() hash.Hash, string) {
	switch strings.ToLower(strings.TrimSpace(n)) {
	case "sha512", "sha-512", "512":
		return sha512.New, "SHA-512"
	default:
		return sha256.New, "SHA-256"
	}
}

func randSalt(nbytes int) []byte { b := make([]byte, nbytes); rand.Read(b); return b }

func readSalt(label string) []byte {
	s := strings.TrimSpace(prompt(label + " (hex, blank = random 16 bytes)"))
	if s == "" {
		return randSalt(16)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		warnMsg("invalid hex, using a random 16-byte salt")
		return randSalt(16)
	}
	return b
}

// storageString builds the portable pbkdf2 hash string.
func storageString(hname string, iter int, salt, dk []byte) string {
	tag := strings.ToLower(strings.ReplaceAll(hname, "-", "")) // SHA-256 -> sha256
	return fmt.Sprintf("pbkdf2_%s$%d$%s$%s", tag,
		iter, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(dk))
}

// verifyStorage checks a password against a pbkdf2 storage string, constant-time.
func verifyStorage(stored, password string) (bool, error) {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || !strings.HasPrefix(parts[0], "pbkdf2_") {
		return false, fmt.Errorf("unrecognised storage format (want pbkdf2_sha256$iter$b64salt$b64key)")
	}
	hf, _ := hashByName(strings.TrimPrefix(parts[0], "pbkdf2_"))
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false, fmt.Errorf("bad iteration count")
	}
	salt, e1 := base64.RawStdEncoding.DecodeString(parts[2])
	want, e2 := base64.RawStdEncoding.DecodeString(parts[3])
	if e1 != nil || e2 != nil || len(want) == 0 {
		return false, fmt.Errorf("bad base64 in stored string")
	}
	got := pbkdf2([]byte(password), salt, iter, len(want), hf)
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// ---------------------------------------------------------------------------
// Interactive handlers
// ---------------------------------------------------------------------------

func doPBKDF2() {
	clear()
	banner()
	header("PBKDF2 Key Derivation")
	pw := prompt("password / passphrase")
	salt := readSalt("salt")
	hf, hname := hashByName(prompt("PRF hash (sha256/sha512) [sha256]"))
	iter := atoiDef(prompt("iterations (default 200000)"), 200000)
	kl := atoiDef(prompt("key length bytes (default 32)"), 32)
	start := time.Now()
	dk := pbkdf2([]byte(pw), salt, iter, kl, hf)
	el := time.Since(start)
	clear()
	banner()
	okMsg("Derived key (PBKDF2-HMAC-" + hname + ")")
	fmt.Println()
	table([]string{"Field", "Value"}, [][]string{
		{"Algorithm", "PBKDF2-HMAC-" + hname},
		{"Iterations", strconv.Itoa(iter)},
		{"Salt (hex)", hex.EncodeToString(salt)},
		{"Key length", strconv.Itoa(kl) + " bytes"},
		{"Time", el.Round(time.Microsecond).String()},
		{"Key (hex)", hex.EncodeToString(dk)},
		{"Key (b64)", base64.StdEncoding.EncodeToString(dk)},
	})
	fmt.Println()
	info("portable storage string:")
	fmt.Println("  " + col(storageString(hname, iter, salt, dk), GY))
	pause()
}

func doHKDF() {
	clear()
	banner()
	header("HKDF (RFC 5869 extract-then-expand)")
	ikmS := prompt("input key material (ikm, plain text)")
	salt := readSalt("salt")
	hf, hname := hashByName(prompt("hash (sha256/sha512) [sha256]"))
	infoCtx := prompt("context/info string (optional)")
	length := atoiDef(prompt("output length bytes (default 32)"), 32)
	prk := hkdfExtract(salt, []byte(ikmS), hf)
	okm, err := hkdfExpand(prk, []byte(infoCtx), length, hf)
	if err != nil {
		errMsg(err.Error())
		pause()
		return
	}
	clear()
	banner()
	okMsg("HKDF output (HMAC-" + hname + ")")
	fmt.Println()
	table([]string{"Field", "Value"}, [][]string{
		{"Salt (hex)", hex.EncodeToString(salt)},
		{"PRK (hex)", hex.EncodeToString(prk)},
		{"Info", infoCtx},
		{"OKM length", strconv.Itoa(length) + " bytes"},
		{"OKM (hex)", hex.EncodeToString(okm)},
		{"OKM (b64)", base64.StdEncoding.EncodeToString(okm)},
	})
	pause()
}

func doVerify() {
	clear()
	banner()
	header("Verify Password vs Storage String")
	info("format: pbkdf2_sha256$<iter>$<b64salt>$<b64key>")
	fmt.Println()
	stored := prompt("stored string")
	pw := prompt("password to check")
	ok, err := verifyStorage(stored, pw)
	if err != nil {
		errMsg(err.Error())
		pause()
		return
	}
	if ok {
		okMsg("PASSWORD MATCH (constant-time compare)")
	} else {
		errMsg("password does NOT match")
	}
	pause()
}

func doBenchmark() {
	clear()
	banner()
	header("PBKDF2 Cost Calibration")
	info("Find the iteration count that reaches a target derivation time.")
	fmt.Println()
	target := atoiDef(prompt("target time in ms (default 250)"), 250)
	pw := []byte("benchmark-password")
	salt := randSalt(16)
	rows := [][]string{}
	for _, iter := range []int{10000, 50000, 100000, 200000, 400000, 800000} {
		start := time.Now()
		pbkdf2(pw, salt, iter, 32, sha256.New)
		el := time.Since(start)
		note := ""
		if el.Milliseconds() >= int64(target) {
			note = col("≥ target", GRN)
		}
		rows = append(rows, []string{strconv.Itoa(iter), el.Round(time.Microsecond).String(), note})
	}
	table([]string{"Iterations", "Time (SHA-256)", "Note"}, rows)
	fmt.Println()
	info(fmt.Sprintf("Pick the smallest iteration count whose time ≥ %d ms on your target hardware.", target))
	pause()
}

func doNotes() {
	clear()
	banner()
	header("KDF Reference")
	txt := `  PBKDF2  (RFC 2898)  — IMPLEMENTED here on crypto/hmac. OWASP: >= 600,000
                          iterations for PBKDF2-HMAC-SHA256 (2023 guidance).

  HKDF    (RFC 5869)  — IMPLEMENTED here. Use to derive several keys from one
                          high-entropy secret (NOT for low-entropy passwords).

  scrypt  (RFC 7914)  — NOT in Go stdlib. golang.org/x/crypto/scrypt.
                          Interactive params: N=32768, r=8, p=1, keyLen=32.

  Argon2id            — NOT in Go stdlib. golang.org/x/crypto/argon2.
                          OWASP: m=19MiB, t=2, p=1 (or m=64MiB, t=3, p=4).

  bcrypt              — NOT in Go stdlib. golang.org/x/crypto/bcrypt.
                          cost=12 is a common 2024+ baseline (max 72-byte pw).

  This tool stays single-file and stdlib-only by design: it offers the two
  HMAC-based KDFs natively and documents the memory-hard ones rather than
  pretending to run them.`
	fmt.Println(col(txt, GY))
	pause()
}

func atoiDef(s string, def int) int {
	if v, e := strconv.Atoi(strings.TrimSpace(s)); e == nil && v > 0 {
		return v
	}
	return def
}

// ---------------------------------------------------------------------------
// Interactive menu
// ---------------------------------------------------------------------------

func menu(title string, items [][2]string) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for i, it := range items {
		fmt.Println("  " + col(pad(fmt.Sprintf("[%d]", i+1), 4), CY+B) + "  " +
			col(pad(it[0], 26), W) + col("─ "+it[1], DIM))
	}
	fmt.Println()
	fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col(pad("Help & Usage", 26), W) + col("─ How to use, every option, CLI flags & examples", DIM))
	fmt.Println("  " + col(pad("[0]", 4), R+B) + "  " + col(pad("Exit", 26), W) + col("─ Quit "+APPNAME, DIM))
	fmt.Println()
	rule()
	return prompt("Select option")
}

func interactive() {
	for {
		c := menu("Main Menu", [][2]string{
			{"PBKDF2 derive key", "RFC 2898, HMAC-SHA256/512"},
			{"HKDF extract+expand", "RFC 5869, derive keys from a secret"},
			{"Verify password", "check vs a pbkdf2 storage string"},
			{"Cost calibration", "iterations for a target time"},
			{"KDF reference", "scrypt / Argon2id / bcrypt params"},
		})
		switch strings.ToLower(c) {
		case "1":
			doPBKDF2()
		case "2":
			doHKDF()
		case "3":
			doVerify()
		case "4":
			doBenchmark()
		case "5":
			doNotes()
		case "h", "help", "?":
			tuiHelp()
		case "0", "00", "q", "exit", "":
			clear()
			okMsg("Goodbye — owlsec.org")
			return
		default:
			warnMsg("unknown selection")
			pause()
		}
	}
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

func usage() {
	banner()
	sec := func(t string) { fmt.Println("  " + col(t, CY+B)) }
	sec("USAGE")
	fmt.Println("    " + APPNAME + " [flags]            (no flags → interactive TUI)")
	fmt.Println()
	sec("MODES")
	fmt.Println("    --pbkdf2            derive a key with PBKDF2 (needs --password)")
	fmt.Println("    --hkdf             derive output with HKDF (needs --ikm)")
	fmt.Println("    --verify STR       verify --password against a pbkdf2 storage string")
	fmt.Println("    --benchmark        print a PBKDF2 iteration/time calibration table")
	fmt.Println()
	sec("PARAMETERS")
	fmt.Println("    --password STR     password / passphrase (PBKDF2, verify)")
	fmt.Println("    --ikm STR          input key material (HKDF)")
	fmt.Println("    --salt HEX         salt in hex (blank = random 16 bytes)")
	fmt.Println("    --info STR         context/info string (HKDF)")
	fmt.Println("    --hash NAME        PRF hash: sha256 (default) | sha512")
	fmt.Println("    --iter N           PBKDF2 iterations (default 200000)")
	fmt.Println("    --len N            output key length in bytes (default 32)")
	fmt.Println()
	sec("OUTPUT")
	fmt.Println("    --quiet            print only the derived value (hex) — scriptable")
	fmt.Println("    --no-color         disable ANSI colour")
	fmt.Println()
	sec("GENERAL")
	fmt.Println("    --demo  --selftest  --version  -h/--help")
	fmt.Println()
	sec("EXAMPLES")
	fmt.Println("    " + APPNAME + " --pbkdf2 --password hunter2 --iter 600000")
	fmt.Println("    " + APPNAME + " --pbkdf2 --password hunter2 --salt 0011223344556677 --quiet")
	fmt.Println("    " + APPNAME + " --hkdf --ikm master-secret --info \"tls key\" --len 48")
	fmt.Println("    " + APPNAME + " --verify 'pbkdf2_sha256$200000$...$...' --password hunter2")
	fmt.Println("    " + APPNAME + " --benchmark")
	fmt.Println()
	rule()
}

func cliPBKDF2(password, saltHex, hashName string, iter, klen int, quiet bool) int {
	if password == "" {
		errMsg("--pbkdf2 needs --password")
		return 2
	}
	salt, err := saltFromHex(saltHex)
	if err != nil {
		errMsg(err.Error())
		return 2
	}
	hf, hname := hashByName(hashName)
	dk := pbkdf2([]byte(password), salt, iter, klen, hf)
	if quiet {
		fmt.Println(hex.EncodeToString(dk))
		return 0
	}
	banner()
	okMsg("Derived key (PBKDF2-HMAC-" + hname + ")")
	fmt.Println()
	table([]string{"Field", "Value"}, [][]string{
		{"Algorithm", "PBKDF2-HMAC-" + hname},
		{"Iterations", strconv.Itoa(iter)},
		{"Salt (hex)", hex.EncodeToString(salt)},
		{"Key (hex)", hex.EncodeToString(dk)},
		{"Key (b64)", base64.StdEncoding.EncodeToString(dk)},
		{"Storage", storageString(hname, iter, salt, dk)},
	})
	return 0
}

func cliHKDF(ikm, saltHex, infoCtx, hashName string, length int, quiet bool) int {
	if ikm == "" {
		errMsg("--hkdf needs --ikm")
		return 2
	}
	salt, err := saltFromHex(saltHex)
	if err != nil {
		errMsg(err.Error())
		return 2
	}
	hf, hname := hashByName(hashName)
	prk := hkdfExtract(salt, []byte(ikm), hf)
	okm, err := hkdfExpand(prk, []byte(infoCtx), length, hf)
	if err != nil {
		errMsg(err.Error())
		return 2
	}
	if quiet {
		fmt.Println(hex.EncodeToString(okm))
		return 0
	}
	banner()
	okMsg("HKDF output (HMAC-" + hname + ")")
	fmt.Println()
	table([]string{"Field", "Value"}, [][]string{
		{"Salt (hex)", hex.EncodeToString(salt)},
		{"PRK (hex)", hex.EncodeToString(prk)},
		{"OKM (hex)", hex.EncodeToString(okm)},
		{"OKM (b64)", base64.StdEncoding.EncodeToString(okm)},
	})
	return 0
}

func saltFromHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return randSalt(16), nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid --salt hex: %v", err)
	}
	return b, nil
}

func runDemo() {
	banner()
	header("Demo — PBKDF2 & HKDF with fixed inputs")
	salt, _ := hex.DecodeString("73616c74") // "salt"
	dk := pbkdf2([]byte("password"), []byte("salt"), 4096, 32, sha256.New)
	okMsg("PBKDF2-HMAC-SHA256  password/salt, c=4096, dkLen=32")
	fmt.Println("  " + col(hex.EncodeToString(dk), W))
	fmt.Println()
	ikm, _ := hex.DecodeString(strings.Repeat("0b", 22))
	hsalt, _ := hex.DecodeString("000102030405060708090a0b0c")
	hinfo, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	prk := hkdfExtract(hsalt, ikm, sha256.New)
	okm, _ := hkdfExpand(prk, hinfo, 42, sha256.New)
	okMsg("HKDF-SHA256  RFC 5869 Test Case 1 (L=42)")
	fmt.Println("  " + col("PRK: "+hex.EncodeToString(prk), W))
	fmt.Println("  " + col("OKM: "+hex.EncodeToString(okm), W))
	_ = salt
	fmt.Println()
	info("Run --selftest to check these against the published RFC vectors.")
}

func main() {
	var (
		fP     = flag.Bool("pbkdf2", false, "")
		fH     = flag.Bool("hkdf", false, "")
		fVer   = flag.String("verify", "", "")
		fBench = flag.Bool("benchmark", false, "")
		fPw    = flag.String("password", "", "")
		fIkm   = flag.String("ikm", "", "")
		fSalt  = flag.String("salt", "", "")
		fInfo  = flag.String("info", "", "")
		fHash  = flag.String("hash", "sha256", "")
		fIter  = flag.Int("iter", 200000, "")
		fLen   = flag.Int("len", 32, "")
		fQuiet = flag.Bool("quiet", false, "")
		fNoCol = flag.Bool("no-color", false, "")
		fDemo  = flag.Bool("demo", false, "")
		fSelf  = flag.Bool("selftest", false, "")
		fVerN  = flag.Bool("version", false, "")
	)
	flag.Usage = usage
	flag.Parse()
	if *fNoCol {
		noColor = true
	}
	switch {
	case *fVerN:
		fmt.Printf("%s %s  (OWL suite — %s / %s)\n", APPNAME, VERSION, AUTHOR, WEBSITE)
		return
	case *fSelf:
		os.Exit(runSelfTest())
	case *fDemo:
		runDemo()
		return
	case *fBench:
		banner()
		header("PBKDF2 Cost Calibration")
		pw := []byte("benchmark-password")
		salt := randSalt(16)
		rows := [][]string{}
		for _, iter := range []int{10000, 50000, 100000, 200000, 400000, 800000} {
			start := time.Now()
			pbkdf2(pw, salt, iter, 32, sha256.New)
			rows = append(rows, []string{strconv.Itoa(iter), time.Since(start).Round(time.Microsecond).String()})
		}
		table([]string{"Iterations", "Time (SHA-256)"}, rows)
		return
	case *fVer != "":
		ok, err := verifyStorage(*fVer, *fPw)
		if err != nil {
			errMsg(err.Error())
			os.Exit(2)
		}
		if ok {
			if !*fQuiet {
				okMsg("PASSWORD MATCH (constant-time compare)")
			}
			os.Exit(0)
		}
		if !*fQuiet {
			errMsg("password does NOT match")
		}
		os.Exit(1)
	case *fP:
		os.Exit(cliPBKDF2(*fPw, *fSalt, *fHash, *fIter, *fLen, *fQuiet))
	case *fH:
		os.Exit(cliHKDF(*fIkm, *fSalt, *fInfo, *fHash, *fLen, *fQuiet))
	default:
		interactive()
	}
}

// ---------------------------------------------------------------------------
// Self-test — checks the KDF engines against published RFC vectors.
// ---------------------------------------------------------------------------

func runSelfTest() int {
	banner()
	header("Self-Test — RFC known-answer vectors")
	pass, fail := 0, 0
	check := func(name string, got, want string) {
		if got == want {
			pass++
			fmt.Println("  " + col("[✔] ", GRN) + col(name, W))
		} else {
			fail++
			fmt.Println("  " + col("[✘] ", R) + col(name, W))
			fmt.Println("        got  " + col(got, GY))
			fmt.Println("        want " + col(want, GY))
		}
	}
	hx := func(b []byte) string { return hex.EncodeToString(b) }

	// PBKDF2-HMAC-SHA256 (RFC 7914 §11 reference vectors).
	check("PBKDF2-SHA256 c=1  dkLen=32",
		hx(pbkdf2([]byte("password"), []byte("salt"), 1, 32, sha256.New)),
		"120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
	check("PBKDF2-SHA256 c=2  dkLen=32",
		hx(pbkdf2([]byte("password"), []byte("salt"), 2, 32, sha256.New)),
		"ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
	check("PBKDF2-SHA256 c=4096 dkLen=32",
		hx(pbkdf2([]byte("password"), []byte("salt"), 4096, 32, sha256.New)),
		"c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
	check("PBKDF2-SHA256 c=4096 dkLen=40 (passwordPASSWORDpassword)",
		hx(pbkdf2([]byte("passwordPASSWORDpassword"), []byte("saltSALTsaltSALTsaltSALTsaltSALTsalt"), 4096, 40, sha256.New)),
		"348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9")

	// HKDF-SHA256 (RFC 5869 Test Case 1).
	ikm, _ := hex.DecodeString(strings.Repeat("0b", 22))
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	hinfo, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	prk := hkdfExtract(salt, ikm, sha256.New)
	check("HKDF-SHA256 RFC5869 TC1 PRK",
		hx(prk),
		"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
	okm, _ := hkdfExpand(prk, hinfo, 42, sha256.New)
	check("HKDF-SHA256 RFC5869 TC1 OKM (L=42)",
		hx(okm),
		"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

	// HKDF-SHA256 Test Case 3 (zero-length salt & info).
	ikm3, _ := hex.DecodeString(strings.Repeat("0b", 22))
	prk3 := hkdfExtract(nil, ikm3, sha256.New)
	check("HKDF-SHA256 RFC5869 TC3 PRK (empty salt)",
		hx(prk3),
		"19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
	okm3, _ := hkdfExpand(prk3, nil, 42, sha256.New)
	check("HKDF-SHA256 RFC5869 TC3 OKM (empty info, L=42)",
		hx(okm3),
		"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")

	// Round-trip: storage string → verify.
	ss := storageString("SHA-256", 1000, []byte("0123456789abcdef"), pbkdf2([]byte("hunter2"), []byte("0123456789abcdef"), 1000, 32, sha256.New))
	if ok, _ := verifyStorage(ss, "hunter2"); ok {
		pass++
		fmt.Println("  " + col("[✔] ", GRN) + col("storage round-trip: correct password accepted", W))
	} else {
		fail++
		fmt.Println("  " + col("[✘] ", R) + col("storage round-trip (accept)", W))
	}
	if ok, _ := verifyStorage(ss, "wrong"); !ok {
		pass++
		fmt.Println("  " + col("[✔] ", GRN) + col("storage round-trip: wrong password rejected", W))
	} else {
		fail++
		fmt.Println("  " + col("[✘] ", R) + col("storage round-trip (reject)", W))
	}

	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("all %d self-tests passed", pass))
		return 0
	}
	errMsg(fmt.Sprintf("%d passed, %d FAILED", pass, fail))
	return 1
}

// ---------------------------------------------------------------------------
// Help & Usage  (interactive menu [H])
// Page 1: in-app guide (what the tool does, every menu option, tips).
// Page 2: the full command-line reference (same text as --help).
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := ""
		for _, w := range words {
			if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
				out = append(out, cur)
				cur = w
			} else if cur == "" {
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}

func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}

func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func owlHelpRule() { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func tuiHelp() {
	clear()
	banner()
	owlHelpRule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	owlHelpRule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	owlHelpRule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	owlHelpCLI()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

var owlHelpAbout = []string{
	"OKDF is a key-derivation playground. It runs PBKDF2 (RFC 2898) to stretch a password into a key, and HKDF (RFC 5869) to derive one or more keys from an existing high-entropy secret. It can also verify a password against a stored pbkdf2 hash in constant time, and calibrate how many iterations your hardware needs for a target derivation time.",
	"PBKDF2 and HKDF are implemented from scratch on the Go standard library (crypto/hmac + SHA-2). The memory-hard KDFs (scrypt, Argon2id, bcrypt) are not in the standard library, so OKDF documents their recommended parameters instead of running them.",
}

var owlHelpFlow = []string{
	"Type the number of an option and press Enter. Each option asks for its inputs; press Enter to accept the default shown in brackets. [H] opens this help, [0] or q quits.",
	"Salts are entered as hex; leave blank for a random 16-byte salt. Everything also works from the command line (see page 2) for scripting.",
}

var owlHelpMenu = []owlHelpItem{
	{"1", "PBKDF2 derive key: enter a password, salt, PRF hash (sha256/sha512), iterations and key length. Prints the key in hex and base64, plus a portable storage string (pbkdf2_sha256$iter$salt$key)."},
	{"2", "HKDF extract+expand: enter input key material, salt, hash, a context/info string and the output length. Use this to derive keys from an already-random secret, NOT from a password."},
	{"3", "Verify password: paste a pbkdf2 storage string and a password; says whether they match (constant-time compare)."},
	{"4", "Cost calibration: enter a target time in ms; shows the derivation time for several iteration counts so you can pick a safe one for your hardware."},
	{"5", "KDF reference: recommended parameters for PBKDF2, HKDF, scrypt, Argon2id and bcrypt, and why only the first two are built in."},
}

var owlHelpTips = []owlHelpItem{
	{"*", "OWASP (2023) recommends at least 600,000 iterations for PBKDF2-HMAC-SHA256. Use [4] to find the count that fits your latency budget."},
	{"*", "PBKDF2 is for passwords (low entropy); HKDF is for splitting one strong secret into several keys. Do not swap them."},
	{"*", "For brand-new systems prefer a memory-hard KDF (Argon2id or scrypt). Option [5] lists their parameters; OKDF shows them rather than running them to stay stdlib-only."},
	{"*", "--quiet on the CLI prints just the derived hex, handy in scripts: KEY=$(OKDF --pbkdf2 --password \"$PW\" --salt \"$S\" --quiet)."},
}

func owlHelpCLI() { usage() }
