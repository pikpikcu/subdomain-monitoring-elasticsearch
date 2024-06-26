package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"crypto/tls"
)

type Options struct {
	Host            string `yaml:"host" validate:"required_without=IP"`
	IP              string `yaml:"ip" validate:"required,ip"`
	Port            int    `yaml:"port" validate:"gte=0,lte=65535"`
	SSL             bool   `yaml:"ssl"`
	SSLVerification bool   `yaml:"ssl-verification"`
	Username        string `yaml:"username" validate:"required"`
	Password        string `yaml:"password" validate:"required"`
	IndexName       string `yaml:"index-name" validate:"required"`

	HttpClient *http.Client `yaml:"-"`
}

type KatanaResponse struct {
	Timestamp string `json:"timestamp"`
	Request   struct {
		Method     string `json:"method"`
		Endpoint   string `json:"endpoint"`
		Tag        string `json:"tag"`
		Attribute  string `json:"attribute"`
		Source     string `json:"source"`
		RawRequest string `json:"raw"`
	} `json:"request"`
	Response struct {
		StatusCode   int               `json:"status_code"`
		Headers      map[string]string `json:"headers"`
		Body         string            `json:"body"`
		Technologies []string          `json:"technologies"`
		RawResponse  string            `json:"raw"`
	} `json:"response"`
}

type Exporter struct {
	url            string
	authentication string
	elasticsearch  *http.Client
}

func NewExporter(option *Options) (*Exporter, error) {
	var ei *Exporter

	var client *http.Client
	if option.HttpClient != nil {
		client = option.HttpClient
	} else {
		client = &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 10,
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: option.SSLVerification},
			},
		}
	}

	scheme := "http://"
	if option.SSL {
		scheme = "https://"
	}
	var authentication string
	if len(option.Username) > 0 && len(option.Password) > 0 {
		auth := base64.StdEncoding.EncodeToString([]byte(option.Username + ":" + option.Password))
		auth = "Basic " + auth
		authentication = auth
	}
	var addr string
	if option.Host != "" {
		addr = option.Host
	} else {
		addr = option.IP
	}
	if option.Port != 0 {
		addr += fmt.Sprintf(":%d", option.Port)
	}
	url := fmt.Sprintf("%s%s/%s/_doc", scheme, addr, option.IndexName)

	ei = &Exporter{
		url:            url,
		authentication: authentication,
		elasticsearch:  client,
	}
	return ei, nil
}

func basicAuthHeader(username, password string) string {
	if username != "" && password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		return "Basic " + auth
	}
	return ""
}

func (exporter *Exporter) Export(katanaResponse KatanaResponse) error {
	req, err := http.NewRequest(http.MethodPost, exporter.url, nil)
	if err != nil {
		return errors.Wrap(err, "could not make request")
	}
	if len(exporter.authentication) > 0 {
		req.Header.Add("Authorization", exporter.authentication)
	}
	req.Header.Add("Content-Type", "application/json")

	body, err := json.Marshal(&katanaResponse)
	if err != nil {
		return errors.Wrap(err, "could not marshal data")
	}
	req.Body = io.NopCloser(bytes.NewReader(body))

	fmt.Printf("Request URL: %s\n", exporter.url)
	fmt.Printf("Request Body: %s\n", body)

	res, err := exporter.elasticsearch.Do(req)
	if err != nil {
		return errors.Wrap(err, "error making request to Elasticsearch")
	}
	defer res.Body.Close()

	if res.StatusCode >= 300 {
		return errors.New("Elasticsearch responded with an error")
	}

	fmt.Printf("Response Status: %s\n", res.Status)
	return nil
}

func (exporter *Exporter) Close() error {
	return nil
}

func main() {
	silentFlag := flag.Bool("silent", false, "Silent mode")
	flag.Parse()

	var config Options
	configFile, err := os.Open("config.yaml")
	if err != nil {
		log.Fatalf("Failed to open config file: %v", err)
	}
	defer configFile.Close()

	decoder := yaml.NewDecoder(configFile)
	err = decoder.Decode(&config)
	if err != nil {
		log.Fatalf("Failed to decode config YAML: %v", err)
	}

	exporter, err := NewExporter(&config)
	if err != nil {
		log.Fatalf("Failed to create exporter: %v", err)
	}
	defer exporter.Close()

	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		reader := bufio.NewReader(os.Stdin)
		for {
			line, err := reader.ReadBytes('\n')
			if err == io.EOF {
				break
			} else if err != nil {
				log.Fatalf("Error reading from stdin: %v", err)
			}
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}

			var katanaResponse KatanaResponse
			err = json.Unmarshal(line, &katanaResponse)
			if err != nil {
				log.Fatalf("Failed to unmarshal JSON from stdin: %v", err)
			}

			err = exporter.Export(katanaResponse)
			if err != nil {
				log.Fatalf("Failed to export data to Elasticsearch: %v", err)
			}
		}
	} else {
		log.Fatal("No input provided")
	}

	if !*silentFlag {
		log.Println("Data exported successfully to Elasticsearch")
	}
}
