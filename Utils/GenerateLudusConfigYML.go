package Utils

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Struct to track domain information and whether it has a primary DC
type DomainControllerTracker struct {
	DomainName   string // Domain name
	HasPrimaryDC bool   // Indicates if the domain already has a primary DC
}

// Function to check if the domain has a primary DC
func isPrimaryRole(tracker DomainControllerTracker, domainName string) bool {
	// Check if the domainName matches and HasPrimaryDC is true
	if tracker.DomainName == domainName && tracker.HasPrimaryDC {
		return true
	}
	return false
}

// Define struct to represent the configuration for each computer
type WindowsConfig struct {
	Sysprep bool `yaml:"sysprep"`
	//InstallAdditionalTools bool `yaml:"install_additional_tools"`
}

type DomainConfig struct {
	FQDN string `yaml:"fqdn"`
	Role string `yaml:"role"`
}

type ComputerConfig struct {
	VMName      string                 `yaml:"vm_name"`
	Hostname    string                 `yaml:"hostname"`
	Template    string                 `yaml:"template"`
	VLAN        int                    `yaml:"vlan"`
	IPLastOctet int                    `yaml:"ip_last_octet"`
	RamGB       int                    `yaml:"ram_gb"`
	RamMinGB    int                    `yaml:"ram_min_gb"`
	CPUs        int                    `yaml:"cpus"`
	Windows     WindowsConfig          `yaml:"windows"`
	Domain      DomainConfig           `yaml:"domain"`
	Roles       []string               `yaml:"roles"`
	RoleVars    map[string]interface{} `yaml:"role_vars"`
}

type ComputerConfig_NoDomain struct {
	VMName      string                 `yaml:"vm_name"`
	Hostname    string                 `yaml:"hostname"`
	Template    string                 `yaml:"template"`
	VLAN        int                    `yaml:"vlan"`
	IPLastOctet int                    `yaml:"ip_last_octet"`
	RamGB       int                    `yaml:"ram_gb"`
	RamMinGB    int                    `yaml:"ram_min_gb"`
	CPUs        int                    `yaml:"cpus"`
	Windows     WindowsConfig          `yaml:"windows"`
	Roles       []string               `yaml:"roles"`
	RoleVars    map[string]interface{} `yaml:"role_vars"`
}

// Define struct to represent the main configuration structure
type LudusConfig struct {
	Ludus []ComputerConfig `yaml:"ludus"`
}

type nonDomainConfig struct {
	LudusNonDomain []ComputerConfig_NoDomain `yaml:""`
}

// Function to generate a single VM configuration
func configVM(vmName, hostname, template string, vlan, ipLastOctet, ramGB, ramMinGB, cpus int, fqdn, role string, roles []string, roleVars map[string]interface{}) ComputerConfig {
	return ComputerConfig{
		VMName:      vmName,
		Hostname:    hostname,
		Template:    template,
		VLAN:        vlan,
		IPLastOctet: ipLastOctet,
		RamGB:       ramGB,
		RamMinGB:    ramMinGB,
		CPUs:        cpus,
		Windows:     WindowsConfig{Sysprep: true},
		Domain:      DomainConfig{FQDN: fqdn, Role: role},
		Roles:       roles,
		RoleVars:    roleVars,
	}
}

// Function to generate a single VM configuration
func configVM_NoDomain(vmName, hostname, template string, vlan, ipLastOctet, ramGB, ramMinGB, cpus int, fqdn, role string, roles []string, roleVars map[string]interface{}) ComputerConfig_NoDomain {
	return ComputerConfig_NoDomain{
		VMName:      vmName,
		Hostname:    hostname,
		Template:    template,
		VLAN:        vlan,
		IPLastOctet: ipLastOctet,
		RamGB:       ramGB,
		RamMinGB:    ramMinGB,
		CPUs:        cpus,
		Windows:     WindowsConfig{Sysprep: true},
		Roles:       roles,
		RoleVars:    roleVars,
	}
}

// GetTemplate takes an operating system name as input and returns the corresponding template
func GetTemplate(osName string, hostName string) string {
	// Normalize input to lowercase for case-insensitive matching
	osName = strings.ToLower(osName)
	hostName = strings.ToLower(hostName)
	//fmt.Println("OS Name: " + osName)
	//fmt.Println("Host Name: " + hostName)

	// Define a map of OS names to template names
	osTemplates := map[string]string{
		"win11-22h2-x64-enterprise-template": "windows 11",
		"win2022-server-x64-template":        "server 2022",
		"win10-22h2-x64-enterprise-template": "windows 10",
		"win2016-server-x64-template":        "server 2016",
		"win2019-server-x64-template":        "server 2019",
	}

	// Iterate over the map and check if the osName contains any template name part
	for template, identifier := range osTemplates {
		if strings.Contains(strings.ToLower(osName), strings.ToLower(identifier)) {

			return template
		}

	}
	//Default to server 2022
	return "win2022-server-x64-template"
}

// Function to generate and write YAML config
func createYMLFile(computers []ComputerConfig, computersNonDomain []ComputerConfig_NoDomain, filename string) error {
	// Create a combined config structure that contains both configurations
	combinedConfig := struct {
		Ludus          []ComputerConfig          `yaml:"ludus"`
		LudusNonDomain []ComputerConfig_NoDomain `yaml:"ludus_non_domain"`
	}{
		Ludus:          computers,
		LudusNonDomain: computersNonDomain,
	}

	// Marshal the combined data into YAML format
	data, err := yaml.Marshal(&combinedConfig)
	if err != nil {
		return fmt.Errorf("error marshalling YAML: %v", err)
	}

	// Write to file
	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return fmt.Errorf("error writing YAML to file: %v", err)
	}

	// Remove the unnecessary string from the file
	err = removeUnnecessaryString(filename)
	if err != nil {
		return fmt.Errorf("error removing unnecessary string: %v", err)
	}

	return nil
}

// removeUnnecessaryString opens the specified file and removes the "ludus_non_domain:" string and empty array
func removeUnnecessaryString(filename string) error {
	// Read the file content
	content, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}
	// Convert to string for easier manipulation
	fileContent := string(content)

	// Replace the unnecessary string and the empty array that follows
	modifiedContent := strings.Replace(fileContent, "ludus_non_domain: []", "", -1)
	// Also handle case where they might be on separate lines
	modifiedContent = strings.Replace(modifiedContent, "ludus_non_domain:", "", -1)

	// Remove any standalone "[]" that might be left on its own line
	lines := strings.Split(modifiedContent, "\n")
	var cleanedLines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "[]" {
			cleanedLines = append(cleanedLines, line)
		}
	}
	modifiedContent = strings.Join(cleanedLines, "\n")

	// Write the modified content back to the file
	err = os.WriteFile(filename, []byte(modifiedContent), 0644)
	if err != nil {
		return fmt.Errorf("error writing modified content: %v", err)
	}
	return nil
}

/*
// removeUnnecessaryString opens the specified file and removes the "ludus_non_domain:" string
func removeUnnecessaryString(filename string) error {
	// Read the file content
	content, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}

	// Convert to string for easier manipulation
	fileContent := string(content)

	// Replace the unnecessary string
	modifiedContent := strings.Replace(fileContent, "ludus_non_domain:", "", -1)

	// Write the modified content back to the file
	err = os.WriteFile(filename, []byte(modifiedContent), 0644)
	if err != nil {
		return fmt.Errorf("error writing modified content: %v", err)
	}

	return nil
}
*/
