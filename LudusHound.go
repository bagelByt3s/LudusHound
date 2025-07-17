package main

import (
	"flag"
	"fmt"
	"os"
	"LudusHound/Utils"
	"strings"
	
)

func main() {
	// Define flags
	server := flag.String("Server", "", "BloodHound Server")
	user := flag.String("User", "", "Neo4j User")
	pass := flag.String("Pass", "", "Neo4j Password")
	output := flag.String("Output", "", "Output file (e.g., Output/LudusRanges.yml)")
	attackPath := flag.String("AttackPath", "", "Attack Path Filename (e.g., AttackPath.json)")
	DC := flag.String("DomainController", "", "Required for AttackPath Argument. Hostname of DC (e.g., DC01)")
	aliveComputers := flag.String("AliveComputers", "", "Comma-separated list of computers (e.g., DC01.specter.domain,Workstation01.specter.domain,DC01.phantom.domain)")
	filesMapJson := flag.String("FilesMapJson", "", "Path to a JSON file containing the files map")
	localRoles := flag.Bool("LocalRoles", false, "Use local Ansible role names in the config. This will pull roles from Ansible/roles")

	// Parse the flags
	flag.Parse()


	// Ensure that either AttackPath or AliveComputers is provided
	if *attackPath == "" && *aliveComputers == "" {
		fmt.Println("Error: You must provide either --AttackPath or --AliveComputers.")
		flag.Usage()
		os.Exit(1)
	}

	//If attackPath json is empty, then query bloodhound and copy everything
	if *attackPath == "" {

		// Check for mutually exclusive flags: --FilesMapJson and --Server, --User, --Pass
		if *filesMapJson != "" {
			// If --FilesMapJson is provided, Server, User, and Pass are not required
			if *server != "" || *user != "" || *pass != "" {
				fmt.Println("Error: --FilesMapJson and --Server/--User/--Pass cannot be used together.")
				flag.Usage()
				os.Exit(1)
			}
		} else {
			// If --FilesMapJson is not provided, Server, User, and Pass are required
			if *server == "" || *user == "" || *pass == "" || *output == "" {
				fmt.Println("Error: Missing required arguments --Server, --User, --Pass, or --FilesMapJson.")
				flag.Usage()
				os.Exit(1)
			}
		}

			
		// Check if either --FilesMapJson is provided, or --Server --User --Pass are provided
		if *filesMapJson != "" {
			
			fmt.Println("\nProvided FilesMapJson file: " + *filesMapJson )
			fmt.Println("")
			fmt.Println("AliveComputers: \n    " + strings.Replace(*aliveComputers, ",", "\n    ", -1))
			fmt.Println("")
			fmt.Println("Output: ", *output)
			fmt.Println("")
			


			//Create Variables ready for creation of Ludus Range
			Utils.CoordinateLudusYMLVariables(*filesMapJson, aliveComputers, *output, *localRoles)


		} else if *server != "" && *user != "" && *pass != "" {
			// Create the bloodHoundUrl based on the server argument
			bloodHoundURL := "http://" + *server + ":7474/db/neo4j/tx/commit"

			// Print the values out loud
			fmt.Printf("\nServer: %s\n", *server)
			fmt.Printf("User: %s\n", *user)
			fmt.Printf("Password: %s\n", *pass)
			fmt.Printf("Output: %s\n", *output)


			filesMapPath := Utils.GetBloodHoundObjects(*user, *pass, bloodHoundURL)
			
			
			//Create Variables ready for creation of Ludus Range
			Utils.CoordinateLudusYMLVariables(filesMapPath, aliveComputers, *output, *localRoles)

		}

		// If AttackPath is not empty, then create lab based on AttackPath Json
	} else {



			
			// Validate required arguments
			if *DC == "" || *attackPath == "" || *output == "" {
				fmt.Println("Error: Missing required arguments --Output, --AttackPath, --DomainController")
				flag.Usage()
				os.Exit(1)
			}
			
			// Parse the domain controller FQDN
			hostname, domain, err := Utils.ParseDomainController(*DC)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			
			// Parse the attack path and generate YAML configuration
		        yamlContent, err := Utils.GenerateLudusYAMLWithAttackPath(hostname, domain, *attackPath, *localRoles)
			if err != nil {
				fmt.Printf("Error parsing attack path: %v\n", err)
				os.Exit(1)
			}
			
			// Write the YAML content to the output file
			err = Utils.WriteLudusConfig_AttackPath(*output, yamlContent)
			if err != nil {
				fmt.Printf("Error writing to file: %v\n", err)
				os.Exit(1)
			}
			
			fmt.Printf("Successfully created Ludus range configuration at: %s\n", *output)





	}




}
