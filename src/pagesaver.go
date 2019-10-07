package main

import (
	"bufio"
	"bytes"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"html/template"
	// "io"
	"io/ioutil"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	// "sync"
	nurl "net/url"
	"time"
	// "github.com/rylio/ytdl"

	"eipfsd"
)

const (
	checkDAG string = "QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH"
)

var (
	indexTemplate   string
	videoTemplate   string
	workingGateways []string
	publicGateways  = []string{
		// https://github.com/ipfs/public-gateway-checker/blob/master/gateways.json
		"https://ap.siderus.io/ipfs/",
		"https://cdn.cwinfo.net/ipfs/",
		"https://cloudflare-ipfs.com/ipfs/",
		"https://eu.siderus.io/ipfs/",
		"https://gateway.blocksec.com/ipfs/",
		"https://gateway.ipfs.io/ipfs/",
		"https://gateway.originprotocol.com/ipfs/",
		"https://gateway.pinata.cloud/ipfs/",
		"https://gateway.serph.network/ipfs/",
		"https://gateway.temporal.cloud/ipfs/",
		"https://google.via0.com/ipfs/",
		"https://hardbin.com/ipfs/",
		"https://ipfs.busy.org/ipfs/",
		"https://ipfs.doolta.com/ipfs/",
		// "https://ipfs.dweb.tools/ipfs/",
		"https://ipfs.eternum.io/ipfs/",
		"https://ipfs.fooock.com/ipfs/",
		"https://ipfs.globalupload.io/",
		"https://ipfs.greyh.at/ipfs/",
		"https://ipfs.infura.io/ipfs/",
		"https://ipfs.io/ipfs/",
		"https://ipfs.jeroendeneef.com/ipfs/",
		"https://ipfs.jes.xxx/ipfs/",
		"https://ipfs.mrh.io/ipfs/",
		"https://ipfs.netw0rk.io/ipfs/",
		"https://ipfs.privacytools.io/ipfs/",
		"https://ipfs.renehsz.com/ipfs/",
		"https://ipfs.sloppyta.co/ipfs/",
		"https://ipfs.stibarc.gq/ipfs/",
		"https://ipfstube.erindachtler.me/ipfs/",
		"https://ipfs.wa.hle.rs/ipfs/",
		"https://ipns.co/",
		"https://jorropo.ovh/ipfs/",
		"https://na.siderus.io/ipfs/",
		"https://ninetailed.ninja/ipfs/",
		"https://permaweb.io/ipfs/",
		"https://rx14.co.uk/ipfs/",
		"https://siderus.io/ipfs/",
		"http://gateway.bdaily.club",
		"https://snap1.d.tube/ipfs/",
	}
)

// IndexData .
type IndexData struct {
	Show      bool
	TargetDAG string
	Gateways  []string
	HasFile   bool
	Filename  string
}

// VideoTemplateData .
type VideoTemplateData struct {
	VideoFilename string
}

// main .
func main() {

	doIPFS()

	checkPublicGateways()

	pageSaver()

}

// pageSaver .
func pageSaver() {

	indexTemplate = stringFile("/app/static/index.html")
	videoTemplate = stringFile("/app/static/video.html")

	mux := http.NewServeMux()
	mux.HandleFunc("/", serveIndex)

	log.Println("Starting pagesaver...")
	workingGateways = append(workingGateways, "https://ipfs.dweb.tools/ipfs/")

	https := makeHTTPSServer(":8000", mux)
	log.Fatal(https.ListenAndServeTLS("", ""))

	// http.ListenAndServe(":8000", mux)

}

func serveIndex(w http.ResponseWriter, r *http.Request) {

	t := template.Must(template.New("index").Parse(indexTemplate))

	switch r.Method {

	case "GET":

		data := IndexData{
			HasFile:  false,
			Filename: "",
			Show:     false,
		}

		file, exist := r.URL.Query()["file"]

		if exist {
			log.Printf("Seeing file: %s", file[0])
			data.HasFile = true
			data.Filename = file[0]
		}

		dag, exist := r.URL.Query()["dag"]
		if exist {
			data.Show = true
			randomizedList := make([]string, len(workingGateways))
			mrand.Seed(time.Now().UTC().UnixNano())
			perm := mrand.Perm(len(workingGateways))
			for i, v := range perm {
				randomizedList[v] = workingGateways[i]
			}
			data.Gateways = randomizedList
			data.TargetDAG = dag[0]
		}

		err := t.Execute(w, data)
		check(err, "templating html")

	case "POST":
		r.ParseForm()

		// targetURL := r.FormValue("targeturl")

		url, urlType := parseURL(r.FormValue("targeturl"))

		// url := fixURL(r.FormValue("targeturl"))

		// log.Printf("Seeing url: %s", url)

		// urlType := checkURLType(url)

		switch urlType {

		case "youtube":
			log.Printf("Seeing Youtube URL: %s", url)

			// filename := "video.mp4"
			filename, _ := getVideoFilename(url)

			dir, err := ioutil.TempDir(os.TempDir(), "ipfs")
			check(err, "making temp dir: "+dir)
			log.Printf("Created temp dir: %s", dir)
			defer os.RemoveAll(dir)

			ytdl, ext := getVideo(url, dir+"/"+filename)
			log.Printf("Seeing video ext: %s", ext)
			log.Printf("youtube-dl:\n%s", ytdl)

			// vid, err := ytdl.GetVideoInfo(url)
			// check(err,"ytdl getting video info: "+url)
			// file, err := os.Create(dir + "/" + filename)
			// defer file.Close()
			// check(err, "creating file: "+dir+"/"+filename)
			// err = vid.Download(vid.Formats[0], file)
			// check(err,"ytdl download video file: "+url)
			// t := template.Must(template.New("index").Parse(videoTemplate))

			// files, err := ioutil.ReadDir(dir+"/")
			// check(err, "reading tmp dir: "+dir)

			// for _, f := range files {
			// 	log.Printf("Seeing video artifact: %s", dir + "/"+f.Name())

			// 		// fmt.Println(f.Name())
			// }
			filewithext := filename+"."+ext
			log.Printf("templating video page with filename: %s", filewithext)

			data := VideoTemplateData{VideoFilename: filewithext}
			// err = t.Execute(file, data)

			
			file, err := os.Create(dir + "/"+filename+".html")
			defer file.Close()
			check(err, "creating file: "+dir + "/"+filename+".html")
			t := template.Must(template.New("index").Parse(videoTemplate))
			err = t.Execute(file, data)
			check(err, "templating html")

			// err = ioutil.WriteFile(dir + "/"+filename+"."+ext+".html", []byte(videoTemplate), 0666)
			// check(err, "Writing file: "+dir + "/"+filename+"."+ext+".html")

			dag := addDir(dir)
			log.Printf("Pagesaver: %s : %s", url, dag)
			mrand.Seed(time.Now().UnixNano())
			for _, server := range workingGateways {
				i := mrand.Intn(3-1) + 1
				if i == 2 {
					go WarmURL(server + dag + "/" + filewithext)
				}
			}

			http.Redirect(w, r, r.URL.Hostname()+"/?dag="+dag+"&file="+filename+".html", http.StatusSeeOther)

		case "nojavascript":
			log.Printf("no javascript URL: %s", url)

			html := monolith(url) // TODO: use --nojs argument to fix lazyloading
			filename, err := getTitle(html)
			if err == nil && filename != "" {
				log.Printf("Finding title: %s", filename)
			} else {
				filename = "index"
			}

			dir, err := ioutil.TempDir(os.TempDir(), "ipfs")
			check(err, "making temp dir: "+dir)
			defer os.RemoveAll(dir)

			err = ioutil.WriteFile(dir+"/"+filename+".html", []byte(html), 0666)
			check(err, "Writing file: "+dir+"/"+filename+".html")

			dag := addDir(dir)
			log.Printf("Pagesaver: %s : %s", url, dag)
			mrand.Seed(time.Now().UnixNano())
			for _, server := range workingGateways {
				i := mrand.Intn(3-1) + 1
				if i == 2 {
					go WarmURL(server + dag + "/" + filename + ".html")
				}
			}

			http.Redirect(w, r, r.URL.Hostname()+"/?dag="+dag+"&file="+filename+".html", http.StatusSeeOther)

		default:
			html := monolith(url)
			filename, err := getTitle(html)
			if err == nil && filename != "" {
				log.Printf("Finding title: %s", filename)
			} else {
				filename = "index"
			}

			dir, err := ioutil.TempDir(os.TempDir(), "ipfs")
			check(err, "making temp dir: "+dir)
			defer os.RemoveAll(dir)

			err = ioutil.WriteFile(dir+"/"+filename+".html", []byte(html), 0666)
			check(err, "Writing file: "+dir+"/"+filename+".html")

			dag := addDir(dir)
			log.Printf("Pagesaver: %s : %s", url, dag)
			mrand.Seed(time.Now().UnixNano())
			for _, server := range workingGateways {
				i := mrand.Intn(3-1) + 1
				if i == 2 {
					go WarmURL(server + dag + "/" + filename + ".html")
				}
			}

			http.Redirect(w, r, r.URL.Hostname()+"/?dag="+dag+"&file="+filename+".html", http.StatusSeeOther)
		}

	default:
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(http.StatusText(http.StatusNotImplemented)))
	}

	return

}

func doIPFS() {
	log.Println("Instanciating ipfs daemon...")
	d := eipfsd.NewDaemon("/app/data/ipfs/")

	log.Println("Initializing ipfs daemon...")
	d.Initialize()

	log.Println("Running ipfs daemon...")
	go d.Run()
}

func getVideo(url, filepath string) (string, string) {
	var stdout bytes.Buffer
	// %(title)s-%(id)s.%(ext)s
	log.Printf("Running youtube-dl to get video file: %s", url)
	cmd := exec.Command(
		"youtube-dl",
		"--restrict-filenames",
		"-k",
		"-o", filepath,
		url,
	)
	cmd.Stdout = &stdout
	err := cmd.Run()
	check(err, "running youtube-dl on url: "+url)
    scanner := bufio.NewScanner(strings.NewReader(string(stdout.Bytes())))
	scanner.Split(bufio.ScanLines)
	var ext string
    for scanner.Scan() {
		// log.Printf("Seeing video file: %s", dir + "/"+f.Name())
		// fmt.Println(scanner.Text())
		if strings.Contains(scanner.Text(), "Merging formats") {
			log.Printf("DEBUG LINE: %s", scanner.Text())

			ext = strings.Split(scanner.Text(), ".")[1]
			log.Printf("DEBUG EXT1: %s", ext)

			ext = strings.TrimSuffix(ext, `"`)
			log.Printf("DEBUG EXT2: %s", ext)

		}
    }
	return string(stdout.Bytes()), ext

}

func getVideoFilename(url string) (filename, ext string) {
	var ystdout bytes.Buffer
	// %(title)s-%(id)s.%(ext)s
	log.Printf("Running youtube-dl to get filename: %s", url)
	ycmd := exec.Command(
		"youtube-dl",
		"--get-filename",
		"--restrict-filenames",
		"-o", "%(title)s-%(id)s.%(ext)s",
		url,
	)
	ycmd.Stdout = &ystdout
	err := ycmd.Run()
	check(err, "running youtube-dl get filename on url: "+url)
	// var tstdout bytes.Buffer
	// // %(title)s-%(id)s.%(ext)s
	// tcmd := exec.Command(
	// 	"tree",
	// 	"/tmp/",
	// )
	// tcmd.Stdout = &tstdout
	// err = tcmd.Run()
	// check(err, "debug")
	splitName := strings.Split(string(ystdout.Bytes()), ".")
	return splitName[0], splitName[1]
}

func parseURL(url string) (curl string, urlType string) {
	if !(strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://")) {
		url = "http://" + url
	}
	purl, err := nurl.Parse(url)
	check(err, "error parsing URL: "+url)
	curl = purl.String()

	switch purl.Hostname() {
	case "www.youtube.com":
		{
			return curl, "youtube"
		}
	case "youtube.com":
		{
			return curl, "youtube"
		}
	case "youtu.be":
		{
			return curl, "youtube"
		}
	case "www.reddit.com":
		{
			return curl, "nojavascript"

		}
	case "medium.com":
		{
			return curl, "nojavascript"
		}
	default:
		{
			return curl, "monolith"
		}
	}
}

func checkPublicGateways() {
	log.Printf("Checking gateway list...")
	for _, gateway := range publicGateways {
		go testGateway(gateway)

	}
}

func testGateway(gateway string) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	// log.Printf("Testing gateway for 0 byte file: %s", gateway)
	res, err := client.Get(gateway + checkDAG)
	if err != nil {
		return
	}
	defer res.Body.Close()
	if res.StatusCode == 200 {
		workingGateways = append(workingGateways, gateway)
		log.Printf("Seeing responsive gateway: %s", gateway)
		return
	}
	log.Printf("Gateway failed: %s", gateway)
}

// WarmURL .
func WarmURL(url string) {
	time.Sleep(time.Duration(mrand.Intn(15)) * time.Second)
	// log.Printf("Pagesaver, warming cache: %s", url)
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		// log.Printf("Failed warming cache: %s", url)
		return
	}
	defer resp.Body.Close()
	// io.Copy(ioutil.Discard, resp.Body)
	split := strings.Split(url, "/")
	gateway := split[0] + "//" + split[1] + split[2] + "/"
	log.Printf("SUCCESS! warming cache: %s", gateway)
	return
}

// fixURL .
// func fixURL(url string) string {
// 	if strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://") {
// 		return url
// 	}
// 	return "http://" + url
// }

// monolith .
func monolith(url string) (html string) {

	dir, err := ioutil.TempDir(os.TempDir(), "monolith")
	check(err, "making temp dir: "+dir)
	defer os.RemoveAll(dir)

	var stdout bytes.Buffer

	cmd := exec.Command("monolith", url)
	cmd.Stdout = &stdout
	err = cmd.Run()
	check(err, "running monolith on url: "+url)
	html = string(stdout.Bytes())
	return html
}

// func checkURLType(url string) (urlType string) {

// 	if strings.HasPrefix(url, "https://www.youtube.com") ||
// 	strings.HasPrefix(url, "https://youtu.be") {
// 		urlType = "video"
// 	} else if strings.HasPrefix(url, "https://www.reddit.com") ||
// 	strings.HasPrefix(url, "https://medium.com") {
// 		urlType = "nojavascript"
// 	} else {
// 		urlType = ""
// 	}

// 	return urlType
// }

func addDir(dir string) (dag string) {

	os.Setenv("IPFS_PATH", "/app/data/ipfs")

	cmd := exec.Command("ipfs", "add", "-qr", dir) // TODO: find a better way
	out, err := cmd.CombinedOutput()
	log.Printf("IPFS add: %s", out)
	check(err, "Adding to ipfs: "+dir)

	// get last line of output, which is root dag
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	var rootDAG string
	for scanner.Scan() {
		rootDAG = scanner.Text()
		log.Printf("ipfs add: %s", rootDAG)
	}

	if rootDAG[:2] != "Qm" {
		return ""
	}

	return rootDAG
}

func getTitle(html string) (string, error) {
	titleStartIndex := strings.Index(html, "<title>")
	if titleStartIndex == -1 {
		return "", errors.New("Cant find open title")
	}
	titleStartIndex += 7
	titleEndIndex := strings.Index(html, "</title>")
	if titleEndIndex == -1 {
		return "", errors.New("Cant find close title")
	}
	r := strings.NewReplacer(
		" ", "_",
		"/", "_",
		":", "-",
		".", "-",
		"(", "",
		")", "",
		`"`, "",
		"'", "",
		",", "",
		"?", "",
		"|", "",
		"__", "_",
		"_.", ".",
	)
	title := r.Replace(strings.TrimSpace(html[titleStartIndex:titleEndIndex]))
	title = r.Replace(title) // again for dual char replace
	if len(title) > 80 {
		return title[0:80], nil
	}
	return title, nil
}

func makeHTTPSServer(port string, mux *http.ServeMux) *http.Server {

	crt := makeSSLCert()

	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		Certificates: []tls.Certificate{crt},
	}
	httpsServer := &http.Server{
		Addr:         port,
		Handler:      logger(mux),
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	return httpsServer
}

func makeSSLCert() tls.Certificate {

	priv, err := rsa.GenerateKey(crand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{""},
			Country:       []string{""},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(crand.Reader, &certTemplate, &certTemplate, priv.Public(), priv)
	if err != nil {
		panic(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	return tlsCert
}

// stringFile .
func stringFile(path string) string {
	fileBytes, err := ioutil.ReadFile(path)
	check(err, "reading file: "+path)
	return string(fileBytes)
}

// logger .
func logger(handler http.Handler) http.Handler {
	log := func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s %s", r.RemoteAddr, r.Method, r.Host, r.URL)
		handler.ServeHTTP(w, r)
	}
	logHandler := http.HandlerFunc(log)
	return logHandler
}

// check .
func check(err error, msg string) {
	if err != nil {
		log.Panicf(msg+` : Error : 
###
%v
###
`, err)
	}
}
