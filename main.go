package main

import(
	sb "google.golang.org/api/safebrowsing/v4"
	"net/http"
	"flag"
	"google.golang.org/api/googleapi/transport"
	"fmt"
	"encoding/json"
	"github.com/ns3777k/go-shodan/shodan"
)

var (
	website = flag.String("website", "", "URL to search if safe or not")
	email = flag.String("email", "", "check if email exists")
	ip = flag.String("ip", "", "scan ip with Shodan")
)

func main() {
	flag.Parse()

	if *website != "" {
		websiteCheck()
	} else if *email != "" {
		emailCheck()
	} else if *ip != "" {
		shodanCheck()
	} else {
		flag.Usage()
		return
	}


}
func shodanCheck() {
	client := shodan.NewClient(nil, "kpIpMqmM9dG3FdBj2QC2ks3cSK1KlRiW")

	host, err := client.GetServicesForHost(*ip, &shodan.HostServicesOptions{History: true, Minify: false})
	if err != nil {
		panic(err)
	}

	fmt.Printf("ISP: %s \nCountry: %s \nOS: %s \nASN: %s \n", host.ISP, host.Country, host.OS, host.ASN)
	for i, v := range host.Vulnerabilities {
		fmt.Printf("Vulnerability %d: %s", i, v)
	}

	//
	//var prettyJSON bytes.Buffer
	//err := json.Indent(&prettyJSON, body, "", "\t")
	//if err != nil {
	//	panic(err)
	//}
	//
	//log.Println("CSP Violation:", string(prettyJSON.Bytes()))
}

func emailCheck(){
	cli2 := http.Client{}
	resp, err := cli2.Get("https://api.hunter.io/v2/email-verifier?email=" + *email + "&api_key=0aa2a8dfe406b01619e840cf5d73e8a87d373fa3")
	if err != nil {
		panic(err)
	}

	res := make(map[string]interface{}, 1)
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&res); err != nil {
		panic(err)
	}
	data := res["data"].(map[string]interface{})
	fmt.Printf("Email: %s \nResult: %s \nScore: %f \n", data["email"], data["result"], data["score"].(float64))
}

func websiteCheck() {
	cli := &http.Client{Transport: &transport.APIKey{Key: "AIzaSyAIREfXCIPuaM4uvt8ash1qJBMgYOdhTGE"}}
	ser, err := sb.New(cli)
	if err != nil {
		panic(err)
	}
	call := ser.ThreatMatches.Find(&sb.FindThreatMatchesRequest{
		Client: &sb.ClientInfo{ClientId: "do-you-even-code", ClientVersion: "1.0"},
		ThreatInfo: &sb.ThreatInfo{
			PlatformTypes:    []string{"ANY_PLATFORM"},
			ThreatTypes:      []string{"THREAT_TYPE_UNSPECIFIED", "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"},
			ThreatEntryTypes: []string{"URL"},
			ThreatEntries: []*sb.ThreatEntry{
				{Url: *website},
			},
		},
	})
	resp, err := call.Do()
	if err != nil {
		panic(err)
	}
	for _, e := range resp.Matches {
		fmt.Println(e.ThreatType)
	}
}