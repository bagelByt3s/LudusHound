package Utils
import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
	"time"
)

/*
ParseComputersJson.go is for the Computer struct. 

LudusHound needs to be able to determine if an "AliveComputer" is a DC or just a member. 
LudusHound will read the computers.json file pulled from BloodHound and save that information to the Computer sturct. 
Computer struct is then queried to determine if a system should be a DC or not when generating the Ludus config.

*/

// Define the structure based on the provided JSON format
type Computer struct {
	DistinguishedName    string   `json:"distinguishedname"`
	Domain               string   `json:"domain"`
	DomainSID            string   `json:"domainsid"`
	Enabled              bool     `json:"enabled"`
	HasLAPS              bool     `json:"haslaps"`
	IsACLProtected       bool     `json:"isaclprotected"`
	IsDC                 bool     `json:"isdc"`
	LastLogon            int64    `json:"lastlogon"`
	LastLogonTimestamp   int64    `json:"lastlogontimestamp"`
	LastSeen             string   `json:"lastseen"`
	Name                 string   `json:"name"`
	ObjectID             string   `json:"objectid"`
	OperatingSystem      string   `json:"operatingsystem"`
	PasswordLastSet      int64    `json:"pwdlastset"`
	SAMAccountName       string   `json:"samaccountname"`
	ServicePrincipalNames []string `json:"serviceprincipalnames"`
	SIDHistory           []string `json:"sidhistory"`
	TrustedToAuth        bool     `json:"trustedtoauth"`
	UnconstrainedDelegation bool  `json:"unconstraineddelegation"`
	WhenCreated          int64    `json:"whencreated"`
}

// Function to parse JSON and print computer data
func parseComputersJson(filename string) ([]Computer, error) {
	// Read the JSON file
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Decode the JSON into a slice of Computer structs
	var computers [][]Computer
	err = json.Unmarshal(data, &computers)
	if err != nil {
		return nil, err
	}

	// Flatten the nested slice to make it easier to work with
	var flatComputers []Computer
	for _, compList := range computers {
		flatComputers = append(flatComputers, compList...)
	}

	return flatComputers, nil
}

//Function to return data from Computer struct 
func GetComputerField(computers []Computer, computerName, field string) (interface{}, error) {
	// Loop through computers to find the one with the matching name
	for _, computer := range computers {

		if computer.Name == computerName {
			// Use reflection to get the field's value
			val := reflect.ValueOf(computer)
			fieldVal := val.FieldByName(field)
			if fieldVal.IsValid() {
				return fieldVal.Interface(), nil
			}
			return nil, fmt.Errorf("field %s not found", field)
		}
	}
	return nil, fmt.Errorf("computer %s not found", computerName)
}


// Function to print the details of a computer
func printComputerDetails(computers []Computer) {
	for _, computer := range computers {
		fmt.Printf("Computer Name: %s\n", computer.Name)
		fmt.Printf("DistinguishedName: %s\n", computer.DistinguishedName)
		fmt.Printf("Domain: %s\n", computer.Domain)
		fmt.Printf("Operating System: %s\n", computer.OperatingSystem)
		fmt.Printf("Enabled: %t\n", computer.Enabled)
		fmt.Printf("SAM Account Name: %s\n", computer.SAMAccountName)
		fmt.Printf("Last Seen: %s\n", computer.LastSeen)

		// Convert Unix timestamps to readable date
		lastLogonTime := time.Unix(computer.LastLogon, 0)
		fmt.Printf("Last Logon: %s\n", lastLogonTime)

		// Convert whenCreated to a readable date
		whenCreatedTime := time.Unix(computer.WhenCreated, 0)
		fmt.Printf("When Created: %s\n", whenCreatedTime)

		fmt.Println("Service Principal Names:")
		for _, spn := range computer.ServicePrincipalNames {
			fmt.Printf("- %s\n", spn)
		}

		// Add a separator for better readability
		fmt.Println("----------------------------------------")
	}
}
