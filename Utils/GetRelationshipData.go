package Utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

type Entry struct {
	Source       string `json:"source"`
	SourceDomain string `json:"sourceDomain"`
	SourceDN     string `json:"sourceDN"`
	Relationship string `json:"relationship"`
	Target       string `json:"target"`
	TargetDomain string `json:"targetDomain"`
	TargetDN     string `json:"targetDN"`
}

/*
// filterByRelationship filters entries based on a specific relationship type.
func filterByRelationship(filePath, relationshipType string, domainName string) ([]Entry, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	var filteredEntries []Entry

	for _, entry := range entries {
		if strings.EqualFold(entry.Relationship, relationshipType) {


			if strings.EqualFold(entry.SourceDomain, domainName) || strings.EqualFold(entry.TargetDomain, domainName) {
				filteredEntries = append(filteredEntries, entry)
			}

		}
	}
	return filteredEntries, nil
}
*/

// Testing function if domain is emtpy

// filterByRelationship filters entries based on a specific relationship type.
func filterByRelationship(filePath, relationshipType string, domainName string) ([]Entry, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}
	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}
	var filteredEntries []Entry

	for _, entry := range entries {
		if strings.EqualFold(entry.Relationship, relationshipType) {
			// Get source domain (from field or extract from source)
			sourceDomain := entry.SourceDomain
			if sourceDomain == "" {
				sourceDomain = extractDomain(entry.Source)
			}

			// Get target domain (from field or extract from target)
			targetDomain := entry.TargetDomain
			if targetDomain == "" {
				targetDomain = extractDomain(entry.Target)
			}

			if strings.EqualFold(sourceDomain, domainName) || strings.EqualFold(targetDomain, domainName) {
				filteredEntries = append(filteredEntries, entry)
			}
		}
	}
	return filteredEntries, nil
}

// extractDomain extracts domain from "USERNAME@HOSTNAME.DOMAIN.COM" format
func extractDomain(identity string) string {
	if parts := strings.Split(identity, "@"); len(parts) == 2 {
		if hostParts := strings.Split(parts[1], "."); len(hostParts) >= 2 {
			return strings.Join(hostParts[len(hostParts)-2:], ".")
		}
	}
	return ""
}

// saveToFile saves the filtered entries to a JSON file.
func saveToFile(entries []Entry, outputFilePath string) error {
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal entries: %w", err)
	}

	if err := ioutil.WriteFile(outputFilePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %w", outputFilePath, err)
	}
	return nil
}

// getValidRelationshipTypes fetches valid relationship types dynamically from Neo4j.
func getValidRelationshipTypes(username, password, neo4jURL string) ([]string, error) {
	query := `
		MATCH ()-[r]->()
		RETURN DISTINCT type(r) AS relationshipType
	`

	payload := Payload{
		Statements: []Statement{
			{Statement: query},
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", neo4jURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(username, password)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error: %d - %s", resp.StatusCode, string(body))
	}

	var graphData GraphResponse
	if err := json.Unmarshal(body, &graphData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal graph data: %w", err)
	}

	var relationshipTypes []string
	for _, row := range graphData.Results[0].Data {
		if len(row.Row) > 0 {
			if relationshipType, ok := row.Row[0].(string); ok {
				relationshipTypes = append(relationshipTypes, relationshipType)
			}
		}
	}
	return relationshipTypes, nil
}

// fetchGraphData fetches the graph data from Neo4j based on a predefined Cypher query.
func fetchGraphData(username, password, neo4jURL string) ([]interface{}, error) {

	query := `
	MATCH (n)-[r]->(m)
	RETURN {
		source: n.name,
		sourceDomain: n.domain,
		sourceDN: n.distinguishedname,
		relationship: type(r),
		target: m.name,
		targetDomain: m.domain,
		targetDN: m.distinguishedname
	}
	`

	payload := Payload{
		Statements: []Statement{
			{Statement: query},
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", neo4jURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(username, password)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error: %d - %s", resp.StatusCode, string(body))
	}

	var graphData GraphResponse
	if err := json.Unmarshal(body, &graphData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	var resultData []interface{}
	for _, row := range graphData.Results[0].Data {
		resultData = append(resultData, row.Row[0])
	}
	return resultData, nil
}

func getRelationshipData(username, password, neo4jURL string, outputFolder string) {

	// Fetch the graph data
	resultData, err := fetchGraphData(username, password, neo4jURL)
	if err != nil {
		log.Fatalf("Error fetching graph data: %v", err)
	}

	// Write the results to a JSON file
	file, err := json.MarshalIndent(resultData, "", "    ")
	if err != nil {
		log.Fatalf("Error marshalling result data: %v", err)
	}

	graphOutputPath := outputFolder + "/Relationships.json"

	fmt.Println("\nRetrieving object relationship mapping for all domains and saving to: ")
	fmt.Println(graphOutputPath + "\n")

	if err := ioutil.WriteFile(graphOutputPath, file, 0644); err != nil {
		log.Fatalf("Error writing to file: %v", err)
	}

}

func parseRelationshipJsonToDomainFolders(relationshipTypes []string, domainName string, domainRelationshipsFolderPath string, graphOutputPath string) {

	// Iterate over each relationship type and filter/save the corresponding entries
	for _, relationshipType := range relationshipTypes {
		filteredEntries, err := filterByRelationship(graphOutputPath, relationshipType, domainName)
		if err != nil {
			log.Fatalf("Error filtering %s: %v", relationshipType, err)
		}
		outputFilePath := domainRelationshipsFolderPath + "/" + relationshipType + ".json"

		if err := saveToFile(filteredEntries, outputFilePath); err != nil {
			log.Fatalf("Error saving to file %s: %v", outputFilePath, err)
		}

		//fmt.Printf("Filtered entries for '%s' saved to %s\n", relationshipType, outputFilePath)

	}

}
