package eipfsd

import (
	"fmt"
	"log"
	"time"
	"os"
	"os/exec"
	"bufio"
	"strings"
	// "bytes"
	// "fmt"
	// "html/template"
	"io"
	// "io/ioutil"
)

// Daemon .
// https://github.com/ipfs/go-ipfs/blob/master/docs/config.md
type Daemon struct {
	Started bool
	Stopped bool
	State   string
	Signal  chan string
	Profile string
	IPFSRepo string
}

// PrintTime .
func PrintTime() {
	currentTime := time.Now().UTC()
	fmt.Println(currentTime.Format("2006/01/02 15:04:05 UTC"))
}

// NewDaemon .
func NewDaemon(repoPath string) *Daemon {
	return &Daemon{
		Started: false,
		Stopped: true,
		State:   "Initializing",
		Signal:  make(chan string),
		Profile: "server",
		IPFSRepo: repoPath,
	}
}

// Run .
func (d *Daemon) Run() {

	started := time.Now().UTC()

	log.Println("Starting ipfs daemon...")
	d.State = "Starting"
	ipfsDaemon("/usr/src/app/data/ipfs/", d)

	finished := time.Now().UTC()
	duration := finished.Sub(started)

	log.Printf("Seeing ipfs fail, ran for %s", duration.String())


}

// Shutdown is a graceful shutdown mechanism
func (d *Daemon) Shutdown() {
	log.Println("Stopping daemon...")
	d.State = "Stopping"
	log.Println("Sending shutdown signal...")
	d.Signal <- "Shutdown"
	for {
		select {
		case sig, exist := <-d.Signal :
			if exist {
				log.Printf("Seeing shutdown select signal: %s", sig)
				d.Signal <- sig
				close(d.Signal)
				log.Println("Exiting shutdown sequence...")
				return
			}
		default:
			break
		}
	}
}

// AddDir .
// TODO: make this work
func (d *Daemon) AddDir(dir string) (dag string) {

	os.Setenv("IPFS_PATH", d.IPFSRepo)

	cmd := exec.Command("ipfs", "add", "-qr", dir)
	out, err := cmd.CombinedOutput()
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

// Initialize .
// TODO: fix everything in here
func (d *Daemon) Initialize() {

	var repoDir string
	repoDir = d.IPFSRepo

	os.Setenv("IPFS_PATH", repoDir)
	os.RemoveAll(repoDir)
	err := os.MkdirAll(repoDir, os.ModePerm)
	check(err, "error making ipfs dir: "+repoDir)

	cmd := exec.Command("ipfs", "init", "--profile=" + d.Profile)
	out, err := cmd.CombinedOutput()
	check(err, "Initializing ipfs repo...")
	log.Println("Initializing ipfs repo... " + string(out))

	cmd = exec.Command("ipfs", "config", "Addresses.API", "/ip4/0.0.0.0/tcp/5001")
	out, err = cmd.CombinedOutput()
	check(err, "Configuring ipfs api address...")
	log.Println("Configuring ipfs api address... " + string(out))

	cmd = exec.Command("ipfs", "config", "Addresses.Gateway", "/ip4/0.0.0.0/tcp/8080")
	out, err = cmd.CombinedOutput()
	check(err, "Configuring ipfs gateway address...")
	log.Println("Configuring ipfs gateway address... " + string(out))

	cmd = exec.Command("ipfs", "config", "--json", "API.HTTPHeaders.Access-Control-Allow-Origin", `["*"]`)
    out, err = cmd.CombinedOutput()
	check(err, "Configuring ipfs access control...")
	log.Println("Configuring ipfs access control... " + string(out))

    // ipfs config --json API.HTTPHeaders.Access-Control-Allow-Methods '["PUT", "GET", "POST"]'

	cmd = exec.Command("ipfs", "config", "Addresses.Swarm", `["/ip4/0.0.0.0/tcp/4001", "/ip4/0.0.0.0/tcp/8081/ws", "/ip6/::/tcp/4001"]`, "--json")
	out, err = cmd.CombinedOutput()
	check(err, "Configuring ipfs swarm addresses...")
	log.Println("Configuring ipfs swarm addresses... " + string(out))

	cmd = exec.Command("ipfs", "config", "--bool", "Swarm.EnableRelayHop", "true")
	out, err = cmd.CombinedOutput()
	check(err, "Configuring ipfs websocket relay...")
	log.Println("Configuring ipfs websocket relay... " + string(out))

	log.Println("Ipfs initialzing done.")

}

// ipfsDaemon .
func ipfsDaemon(dir string, d *Daemon) {

	cmd := exec.Command("ipfs", "daemon", "--migrate=true")
	stdout, _ := cmd.StdoutPipe()
	err := cmd.Start()
	check(err, "Starting ipfs daemon...")
	reader := bufio.NewReader(stdout)

	go func(reader *bufio.Reader, stdout io.ReadCloser) {
		line, err := reader.ReadString('\n')
		for err == nil {
			log.Printf("IPFS: %s", line)
			line, err = reader.ReadString('\n')
		}
	}(reader, stdout)

	err = cmd.Wait()
	check(err, "Wait trigger seen ipfs cmd...")

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
