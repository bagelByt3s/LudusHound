package Utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// Payload structure for the request to Neo4j
type Payload struct {
	Statements []Statement `json:"statements"`
}


// Statement structure for the query
type Statement struct {
	Statement string `json:"statement"`
}



// GraphResponse structure to parse Neo4j response
type GraphResponse struct {
	Results []Result `json:"results"`
}

// Result structure containing data from the query
type Result struct {
	Data []Data `json:"data"`
}

// Data structure to hold individual row data
type Data struct {
	Row []interface{} `json:"row"`
}

func QueryNeo4j(query, user, pass, server string) ([]interface{}, error) {
	// Prepare the payload with the query
	payload := Payload{
		Statements: []Statement{
			{Statement: query},
		},
	}

	// Marshal the payload into JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create the HTTP request
	req, err := http.NewRequest("POST", server, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set request headers and authentication
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(user, pass)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check if the response status is OK
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error: %d - %s", resp.StatusCode, string(body))
	}

	// Parse the response into a GraphResponse structure
	var graphData GraphResponse
	if err := json.Unmarshal(body, &graphData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal graph data: %w", err)
	}

	// Extract data from the response in a flexible way
	var resultData []interface{}
	for _, result := range graphData.Results {
		for _, row := range result.Data {
			// Append each row's values (as a slice of interfaces) to the result data
			resultData = append(resultData, row.Row)
		}
	}

	// Return the collected data
	return resultData, nil
}
