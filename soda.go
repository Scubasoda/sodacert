package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	certstream "github.com/CaliDog/certstream-go"
	"github.com/fatih/color"
	"golang.org/x/net/idna"
)

var (
	// regDomainSlice is a slice of strings used to store domain names
	regDomainSlice []string
	fENGAGED       bool
	hashDiv        string
	// p is an instance of the idna.Profile struct
	p *idna.Profile
	// punyDomainSlice is a slice of punycode encoded domain names
	punyDomainSlice []string
	// clear is a map of function clear that is used to clear the terminal screen
	clear map[string]func()
	// sem is a channel that limits the number of concurrent goroutines
	sem = make(chan struct{}, 100)
	// wg is a WaitGroup used to wait for all goroutines to complete
	wg sync.WaitGroup
	// thisJsProfile is an instance of the JsProfile struct
	thisDomainProfile *DomainProfile
	// jsProfileSlice is a slice of JsProfile instances
	domainProfileSlice []*DomainProfile
	domainProfilesJson []byte
)

type DomainProfile struct {
	Domain          *string   `json:"domain"`
	JsEndpoints     []*string `json:"jsEndpoints"`
	JarmFingerprint *string   `json: jarmFingerprint`
}

func init() {
	// Init clear funcs
	clear = make(map[string]func())
	clear["linux"] = func() {
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
	clear["windows"] = func() {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}

	// Init the hashDivider for UI
	hashDiv = "##-DAP?-######################################################-:)-###"

	// CLear screen and print banner
	callClear()
	printBanner()

}

func callClear() {
	value, ok := clear[runtime.GOOS]
	if ok {
		value()
	} else {
		panic("Unsupported platform...can't clear screen!")
	}
}

func printHashDiv() {
	// Set engaged flag to true, so no other routines can be run
	fENGAGED = true
	color.Set(color.FgHiRed, color.Bold)
	fmt.Printf("\n%s\n", hashDiv)
	color.Unset()
	// Set engaged flag to false, so other routines can be run
	fENGAGED = false
}

// Print ASCII art banner for the live Certstream viewer
func printLive() {
	// Set engaged flag to true, so no other routines can be run
	fENGAGED = true
	liveAscii, err := ioutil.ReadFile("resources/live.txt")
	if err != nil {
		log.Fatal("Error reading ascii art from banner file: ", err)
	}
	color.Set(color.FgHiCyan, color.Bold)
	fmt.Printf("%s\n", string(liveAscii))
	color.Unset()
	printHashDiv()
	// Set engaged flag to false, so other routines can be run
	fENGAGED = false
}

func printBanner() {
	// Set engaged flag to true, so no other routines can be run
	fENGAGED = true
	// Print banner
	banner, err := ioutil.ReadFile("resources/banner.txt")
	if err != nil {
		log.Fatal("Error reading ascii art from banner file: ", err)
	}
	color.Set(color.FgHiCyan, color.Bold)
	fmt.Printf("%s", string(banner))
	color.Unset()
	printHashDiv()
	color.Set(color.FgHiCyan, color.Bold)
	fmt.Println("\nAvailable commands:")
	color.Set(color.FgHiGreen, color.Bold)
	fmt.Print("\n  => show:		")
	color.Unset()
	fmt.Print("Show live certstream listener\n")
	color.Set(color.FgHiGreen, color.Bold)
	fmt.Print("\n  => quit:		")
	color.Unset()
	fmt.Print("Exit program\n\n")
	fmt.Print("sodacert ~> ")

}

func startCertStreamListener() {
	// The false flag specifies that we want heartbeat messages.
	stream, errStream := certstream.CertStreamEventStream(false)
	for {
		select {
		case jq := <-stream:
			messageType, err := jq.String("message_type")

			if err != nil {
				log.Println("Error decoding jq string")
			}
			_ = messageType
			// Get CN (commonname)
			commonName, _ := jq.String("data", "leaf_cert", "subject", "CN")
			var cryptoRegexp = regexp.MustCompile(`(hacking|hitman|carding|fullz|dumps|banklogs|counterfeit|passport|cocaine|meth|heroin)`)
			if cryptoRegexp.MatchString(commonName) {
				if strings.Contains(commonName, "xn--") {
					// Raw Punycode has no restrictions and does no mappings.
					p = idna.New()
					puny, err := p.ToUnicode(commonName)
					if err != nil {
						log.Println(err)
					}
					isDuplicate := false
					for _, s := range punyDomainSlice {
						if s == puny {
							isDuplicate = true
							break
						}
					}
					// Append newString to slice if it's not a duplicate
					if !isDuplicate {
						punyDomainSlice = append(punyDomainSlice, puny)
					}

				} else {
					isDuplicate := false
					for _, s := range regDomainSlice {
						if s == commonName {
							isDuplicate = true
							break
						}
					}
					// Append newString to slice if it's not a duplicate
					if !isDuplicate {
						regDomainSlice = append(regDomainSlice, commonName)
					}
				}

			}

		case err := <-errStream:
			_ = err
		}
	}
}

func main() {
	// Start certstream listener
	go startCertStreamListener()
	// Run function to auto getjs and monkeycheck every 60 seconds (default)
	var inputBuff string
	for {
		inputBuff = string("")
		fmt.Scan(&inputBuff)
		switch inputBuff {
		case "quit", "q":
			{
				os.Exit(0)
			}
		case "show":
			{
				stop2 := make(chan struct{})
				go func() {
					ticker := time.Tick(100 * time.Millisecond)
					for {
						select {
						case <-ticker:
							callClear()
							printLive()
							color.Set(color.FgHiGreen, color.Bold)
							fmt.Println("\nNormal domains:")
							color.Unset()
							for i := range regDomainSlice {
								fmt.Printf("%s, ", regDomainSlice[i])
							}
							/*
								color.Set(color.FgHiRed, color.Bold)
								fmt.Println("\n\nPuny domains:")
								color.Unset()
								for i := range punyDomainSlice {
									fmt.Printf("%s, ", punyDomainSlice[i])
								}
							*/
							fmt.Print("\n")
							printHashDiv()
							color.Set(color.FgHiCyan, color.Bold)
							fmt.Print("\nHit enter to go back to main menu: ")
							color.Unset()
						case <-stop2:
							return
						}
					}
				}()
				input := bufio.NewScanner(os.Stdin)
				input.Scan()
				stop2 <- struct{}{}
				callClear()
				printBanner()

			}

		default:
			{
				fmt.Println("Try entering a valid command next time bozo!")
				time.Sleep(600 * time.Millisecond)
				callClear()
				printBanner()
			}
		}
	}
}
