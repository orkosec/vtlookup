package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type channelData struct {
	bytes     []byte
	hashValue string
}

type VirusTotalResponse struct {
	Data VirusTotalData `json:"data"`
	Hash string         `json:"hash"`
}

type malwareResponse struct {
	Hash            string            `json:"hash"`
	Status          string            `json:"status"`
	NumberOfReports int               `json:"numberOfReports"`
	HarmlessVotes   int               `json:"harmlessVotes"`
	MaliciousVotes  int               `json:"maliciousVotes"`
	OriginalName    string            `json:"originalName"`
	SandboxVerdicts map[string]string `json:"sandbox_verdicts,omitempty"`
}

type SandboxVerict struct {
	Category              string   `json:"category"`
	SandboxName           string   `json:"sandbox_name"`
	MalwareClassification []string `json:"malware_classification"`
	Confidence            int      `json:"confidence,omitempty"`
	MalwareName           []string `json:"malware_names,omitempty"`
}

type VirusTotalData struct {
	Attributes VirusTotalAttributes `json:"attributes"`
}

type VirusTotalAttributes struct {
	// LastAnalysisResults map[string]interface{} `json:"last_analysis_results"`
	TotalVotes struct {
		Harmless  int `json:"harmless"`
		Malicious int `json:"malicious"`
	} `json:"total_votes"`
	LastAnalysisStats struct {
		Harmless         int `json:"harmless"`
		TypeUnsupported  int `json:"type-unsupported"`
		Suspicious       int `json:"suspicious"`
		ConfirmedTimeout int `json:"confirmed-timeout"`
		Timeout          int `json:"timeout"`
		Failure          int `json:"failure"`
		Malicious        int `json:"malicious"`
		Undetected       int `json:"undetected"`
	} `json:"last_analysis_stats"`
	SignatureInfo struct {
		OriginalName string `json:"original name"`
	} `json:"signature_info"`
	SandboxVerdicts map[string]SandboxVerict `json:"sandbox_verdicts"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type Config struct {
	APITimeout time.Duration
	APIKey     string
}

func loadConfig() Config {

	timeout := time.Second * 10
	apiKey := os.Getenv("VIRUSTOTAL_API_KEY") // Get the API key from env

	return Config{
		APITimeout: timeout,
		APIKey:     apiKey,
	}
}

func GetHash(w http.ResponseWriter, req *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	config := loadConfig()

	resultChan := make(chan channelData)
	errChan := make(chan error)

	err := req.ParseForm()
	if err != nil {
		errChan <- fmt.Errorf("failed to parse form: %v", err)
		return
	}
	h := req.FormValue("hash")
	hashSlice := strings.Split(h, ",")

	wg := sync.WaitGroup{}

	for _, v := range hashSlice {
		wg.Add(1)
		go GetObject(v, resultChan, errChan, config)
	}

	for i := 0; i < len(hashSlice); i++ {
		go func() {
			select {
			case result := <-resultChan:
				jsonResponse, err := malwareCheck(result)
				if err != nil {
					log.Printf("error processing response: %v", err)
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode((ErrorResponse{Error: "internal server error"}))
				}
				json.NewEncoder(w).Encode(jsonResponse)

			case err := <-errChan:
				log.Printf("error in API request: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(ErrorResponse{Error: err.Error()})
			}
			wg.Done()
		}()

	}
	wg.Wait()
}

func LoadHash(filename string) {

	resultChan := make(chan channelData)
	errChan := make(chan error)
	config := loadConfig()

	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file:", err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	var hashSlice []string

	for scanner.Scan() {
		line := scanner.Text()
		// fmt.Println(line)
		hashSlice = append(hashSlice, line)
	}

	if err := scanner.Err(); err != nil {
		log.Println("Error reading file", err)
	}

	wg := sync.WaitGroup{}

	for _, v := range hashSlice {
		wg.Add(1)
		go GetObject(v, resultChan, errChan, config)
	}

	for i := 0; i < len(hashSlice); i++ {
		go func() {
			select {
			case result := <-resultChan:
				jsonResponse, err := malwareCheck(result)
				if err != nil {
					log.Printf("error processing response: %v\n", err)
				}

				if jsonResponse.Status == "malicious" && jsonResponse.NumberOfReports >= 5 {
					log.Printf(color.RedString("%#v\n", jsonResponse))
				} else {
					log.Printf("%#v\n", jsonResponse)
				}

			case err := <-errChan:
				log.Printf("error in API request: %v\n", err)
			}
			wg.Done()
		}()

	}
	wg.Wait()

}

func GetObject(hash string, resultChan chan<- channelData, errChan chan<- error, config Config) {

	client := &http.Client{
		Timeout: config.APITimeout,
	}

	myUrl := "https://www.virustotal.com/api/v3/files/" // "https://www.virustotal.com/api/v3/files/id"

	apiPath := fmt.Sprintf("%v%v", myUrl, hash)

	req, err := http.NewRequest("GET", apiPath, nil)
	if err != nil {
		errChan <- err
		return
	}
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", config.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("error making API request: %v", err)
		errChan <- fmt.Errorf("error making API request: %v", err)
		return
	}

	if resp.StatusCode == http.StatusNotFound {
		// log.Printf("no match found for hash %s with status code: %d", hash, resp.StatusCode)
		errChan <- fmt.Errorf("no match found for the hash %v with status code: %d", hash, resp.StatusCode)
		return
	}

	if resp.StatusCode != http.StatusOK {
		// log.Printf("API request failed for hash %s with status code: %d", hash, resp.StatusCode)
		errChan <- fmt.Errorf("API request failed with status code: %d", resp.StatusCode)
		return
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		errChan <- err
		return
	}

	resultChan <- channelData{bytes: body, hashValue: hash}

}

func malwareCheck(t channelData) (malwareResponse, error) {

	v := VirusTotalResponse{}

	if err := json.Unmarshal(t.bytes, &v); err != nil {
		return malwareResponse{}, fmt.Errorf("error unmarshaling JSON: %v", err)
	}

	// https://developers.virustotal.com/reference/url-object#:~:text=total_votes%20%3A%20containing%20the,integer%3E%20number%20of%20negative%20votes.
	hv := v.Data.Attributes.TotalVotes.Harmless
	mv := v.Data.Attributes.TotalVotes.Malicious       //  totalvotes is unweighted number of total votes from the community, divided in "harmless" and "malicious":
	m := v.Data.Attributes.LastAnalysisStats.Malicious // malicious: <integer> number of reports(vendors) saying that is malicious.
	on := v.Data.Attributes.SignatureInfo.OriginalName

	hash := t.hashValue

	// if h == 1 && m > 50 {
	if m >= 1 {
		sandboxmap := make(map[string]string)
		sv := make(map[string]SandboxVerict)
		sandboxVerdicts := v.Data.Attributes.SandboxVerdicts
		for sandboxName, verdict := range sandboxVerdicts {
			sv[sandboxName] = SandboxVerict{
				Category:    verdict.Category,
				SandboxName: sandboxName,
				// MalwareClassification: verdict.MalwareClassification,
				Confidence: verdict.Confidence,
				// MalwareName: verdict.MalwareName,
			}
			sandboxmap[sv[sandboxName].SandboxName] = sv[sandboxName].Category
		}
		return malwareResponse{Hash: hash, Status: "malicious", NumberOfReports: m, HarmlessVotes: hv, MaliciousVotes: mv, OriginalName: on, SandboxVerdicts: sandboxmap}, nil
	}

	return malwareResponse{Hash: hash, Status: "not malicious"}, nil

}
