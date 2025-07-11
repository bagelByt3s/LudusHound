package Utils

import (
	"fmt"
	"log"
	"os"
	"encoding/json"
)

/*
GetBloodHoundObjects.go is in charge of querying and authenticating to the BloodHound server and saving objects and relationship data

*/

// Define the structure for DomainFilesMap
type DomainFilesMap struct {
	Domain   string
	Datatype string
	Filename string
	Filepath string
}


func GetBloodHoundObjects( user, pass, bloodHoundURL string) (string) {

	CreateDirIfNotExists("./Tmp")
	workingFolder, _ := CreateUniqueFolder("./Tmp")

	//Create Relationships folder
	relationshipsFolderPath := workingFolder + "/Relationships"
	CreateDirIfNotExists(relationshipsFolderPath)



	fmt.Println("Directory to save BloodHound Files: " + workingFolder + "\n")

	//Get Domains
	query := `
		MATCH (n:Domain)
		RETURN n.name
	`
	//Query neo4j for all domains
	domains, err := QueryNeo4j(query, user, pass, bloodHoundURL)
	if err != nil {
		log.Fatalf("Error querying Neo4j: %v", err)
		
	}

	// A slice to store DomainFilesMap instances. 
	// This will store data to be used later
	// Format: domain, data type, filename, fileFullPath
	// EX: Specter.domain, Users, Users.json, /opt/Working/Users/Users.json

	var filesMap []DomainFilesMap
	
	// Iterate over each domain and create a folder and request respective AD Objects
	for _, domainEntry := range domains {
		// Type assertion to access the first element in the slice (domain name)
		if domainName, ok := domainEntry.([]interface{})[0].(string); ok {
			// Construct the folder path for the domain
			domainFolderPath := fmt.Sprintf("%s/%s", workingFolder, domainName)
			//Create Folder per domain
			CreateDirIfNotExists(domainFolderPath)
			
		
		fmt.Println("Domain Identified: ", domainName)
		fmt.Println("Retreiving AD Objects for ", domainName)

		//Loop through objects and query data
		labels := []string{
			"GPO", "RootCA", "User", "OU", "Domain", "NTAuthStore", "Container", "AIACA",
			"Group", "Computer", "EnterpriseCA",
			"IssuancePolicy", "Base", "CertTemplate",
		}

		// Loop through each label
		for _, label := range labels {
			// Construct the Cypher query for each label
			query := `
				MATCH (n:` +label+ `)
				WHERE n.domain = "` + domainName + `"
				RETURN n
			`
			// Call the queryNeo4j function to execute the query and get users
			data, err := QueryNeo4j(query, user, pass, bloodHoundURL)
			if err != nil {
				log.Fatalf("Error querying Neo4j: %v", err)
				
			}

			// Define the path to save the result file
			path := workingFolder + "/" + domainName + "/" + label + "s.json"
			filePath, _ := getAbsolutePath(path)

			// Save the data to a file using writeFile function
			if err := writeFile(filePath, data); err != nil {
				log.Fatalf("Error saving  data to file: %v", err)
			}

			//fmt.Println(label + " data successfully saved to " + filePath)

			// Store the relevant info in the filesMap
			filesMap = append(filesMap, DomainFilesMap{
				Domain:   domainName,
				Datatype: label,
				Filename: label + "s.json",
				Filepath: filePath,
			})

			/* Example on how to extract data from fileMap
			// Print out the filesMap entries
			fmt.Println("\nFiles Map:")
			for _, file := range filesMap {
				fmt.Printf("Domain: %s, Datatype: %s, Filename: %s, Filepath: %s\n",
					file.Domain, file.Datatype, file.Filename, file.Filepath)
			}
			*/

			

		}

	
		//Get DomainTrustInfo per Domain

		//Folder path where relationship data will be stored 
		domainRelationshipsFolderPath := workingFolder + "/" + domainName + "/Relationships"
		CreateDirIfNotExists(domainRelationshipsFolderPath)

		query := `
		MATCH p=(n:Domain)-[r:TrustedBy]->(m:Domain)
		WHERE n.name = "` + domainName + `"
			RETURN {
				SourceDomain: n.name, 
				Direction: 'trustedby',
				TrustType: r.trusttype, 
				TargetDomain:  m.name	
			}
		`
		// Call the queryNeo4j function to execute the query and get users
		data, err := QueryNeo4j(query, user, pass, bloodHoundURL)
		if err != nil {
			log.Fatalf("Error querying Neo4j: %v", err)
			
		}

		// Define the path to save the result file
		path := workingFolder + "/" + domainName + "/Relationships/DomainTrusts.json"
		filePath, _ := getAbsolutePath(path)

		//fmt.Println("Saving Domain trust data to " + filePath)
		// Save the data to a file using writeFile function
		if err := writeFile(filePath, data); err != nil {
			log.Fatalf("Error saving  data to file: %v", err)
		}
	



		}
		
		
	}

	//Get Relationship Data
	getRelationshipData(user, pass, bloodHoundURL, relationshipsFolderPath)

	// Fetch valid relationship types dynamically from Neo4j
	relationshipTypes, err := getValidRelationshipTypes(user, pass, bloodHoundURL )
	if err != nil {
		log.Fatalf("Error getting relationship types: %v", err)
	}

	// fmt.Println("Valid Relationship Types: ", relationshipTypes)

	// Iterate over each domain and create a folder and request respective AD Objects
	for _, domainEntry := range domains { 
		if domainName, ok := domainEntry.([]interface{})[0].(string); ok {

		
		
		//Folder path where relationship data will be stored 
		domainRelationshipsFolderPath := workingFolder + "/" + domainName + "/Relationships"
		CreateDirIfNotExists(domainRelationshipsFolderPath)

		//fmt.Println ("Parsing relationships for " + domainName + " and saving to " + domainRelationshipsFolderPath)

		//Absolute path to relationships json to parse
		masterRelationshipJsonPath := workingFolder + "/Relationships/Relationships.json"

		parseRelationshipJsonToDomainFolders(relationshipTypes, domainName, domainRelationshipsFolderPath, masterRelationshipJsonPath )
		}
	}

	//Get DomainTrust info for all domains

	//Folder path where relationship data will be stored 
	masterDomainTrustPathPath := workingFolder + "/Relationships/DomainTrusts.json"


	query = `
			MATCH p=(n:Domain)-[r:TrustedBy]->(m:Domain)
			RETURN {
				SourceDomain: n.name, 
				Direction: 'trustedby',
				TrustType: r.trusttype, 
				TargetDomain:  m.name	
			}
	`
		
	
	// Call the queryNeo4j function to execute the query and get users
	data, err := QueryNeo4j(query, user, pass, bloodHoundURL)
	if err != nil {
		log.Fatalf("Error querying Neo4j: %v", err)
		
	}

	// Define the path to save the result file

	filePath, _ := getAbsolutePath(masterDomainTrustPathPath)

	//fmt.Println()
	//fmt.Println("Retrieving object relationship mapping for all domains and saving to:")
	//fmt.Println(filePath)
	//fmt.Println()

	// Save the data to a file using writeFile function
	if err := writeFile(filePath, data); err != nil {
		log.Fatalf("Error saving  data to file: %v", err)
	}




	filesMapPath := workingFolder + "/filesMap.json"

	// Open the file for writing
	file, err := os.Create(filesMapPath)
	if err != nil {
		log.Fatalf("Error creating file: %v", err)
	}
	defer file.Close()

	// Convert the data to JSON format
	jsonData, err := json.MarshalIndent(filesMap, "", "  ")
	if err != nil {
		log.Fatalf("Error marshaling data to JSON: %v", err)
	}

	// Write the JSON data to the file
	_, err = file.Write(jsonData)
	if err != nil {
		log.Fatalf("Error writing data to file: %v", err)
	}

	fmt.Printf("Data successfully saved to %s\n", filesMapPath)

	return filesMapPath

}

	


