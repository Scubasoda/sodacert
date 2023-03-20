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

	/*
			!!!! Only need the following for scraping html/js !!!!

		// sem is a channel that limits the number of concurrent goroutines
		sem = make(chan struct{}, 100)
		// wg is a WaitGroup used to wait for all goroutines to complete
		wg sync.WaitGroup
	*/
)

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
	fmt.Print("\n  => output:		")
	color.Unset()
	fmt.Print("Show the contents of domains.txt file in output folder\n")
	color.Set(color.FgHiGreen, color.Bold)
	fmt.Print("\n  => quit or q:		")
	color.Unset()
	fmt.Print("Exit program\n")
	printHashDiv()
	fmt.Print("\nsodacert ~> ")

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
			var cryptoRegexp = regexp.MustCompile(`(hacker|whitehat|greyhat|grayhat|blackhat|simswap|drainer|hacking|hitman|carding|fullz|silkroad|alphabay|dredd|tortodoor|dumps|banklogs|counterfeit|passport|cocaine|meth|heroin)`)
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

func readDomainsFile() {
	file, err := os.Open("./output/domains.txt")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
	}
}

func dedupeDomainsFile() {
	// Open file for reading
	file, err := os.Open("./output/domains.txt")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// Read file contents into memory
	scanner := bufio.NewScanner(file)
	lines := make([]string, 0)
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
	}

	// Remove duplicate lines
	uniqueLines := make(map[string]bool)
	for _, line := range lines {
		if !uniqueLines[line] {
			uniqueLines[line] = true
		}
	}

	// Overwrite file with unique lines
	file, err = os.OpenFile("./output/domains.txt", os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for line := range uniqueLines {
		_, err = writer.WriteString(line + "\n")
		if err != nil {
			panic(err)
		}
	}
	err = writer.Flush()
	if err != nil {
		panic(err)
	}

}

func main() {
	// Start certstream listener
	go startCertStreamListener()

	ticker := time.NewTicker(2500 * time.Millisecond)

	// create goroutine to write data to file every 10 seconds
	go func() {
		// read existing lines in the file
		file, err := os.OpenFile("./output/domains.txt", os.O_RDONLY, 0666)
		if err != nil {
			panic(err)
		}
		defer file.Close()

		existingLines := make(map[string]bool) // map to track existing lines in the file
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			existingLines[scanner.Text()] = true
		}

		for {
			select {
			case <-ticker.C:
				curDomainSlice := regDomainSlice
				file, err := os.OpenFile("./output/domains.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
				if err != nil {
					panic(err)
				}

				// write new domains to file and update existingLines set
				writer := bufio.NewWriter(file)
				for _, domain := range curDomainSlice {
					if !existingLines[domain] {
						_, err = writer.WriteString(domain + "\n")
						if err != nil {
							panic(err)
						}
						existingLines[domain] = true
					}
				}
				writer.Flush()
				file.Close()
			}
		}
	}()

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

							color.Set(color.FgHiRed, color.Bold)
							fmt.Println("\n\nPuny domains:")
							color.Unset()
							for i := range punyDomainSlice {
								fmt.Printf("%s, ", punyDomainSlice[i])
							}

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
		// Read domain output file and print to terminal (STDOUT)
		case "output":
			{
				callClear()
				printHashDiv()
				fmt.Println()
				readDomainsFile()
				printHashDiv()
				color.Set(color.FgHiCyan, color.Bold)
				fmt.Print("\nHit enter to go back to main menu: ")
				color.Unset()
				input := bufio.NewScanner(os.Stdin)
				input.Scan()
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
