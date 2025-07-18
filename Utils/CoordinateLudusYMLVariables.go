package Utils
	
import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"os"
	"path/filepath"
)

/*

CoordinateLudusYMLVariables.go is for the following:

- The logic used to determine which ansible roles go to which system 

	Domain Controllers get x,y,z ansible roles 
	Members get x,y,z ansible roles 
	Child Domain Controlelrs get x,y,z ansible roles 
	Members of Child DC's get x,y,z ansible roles

- Determining the variables values for each system config 
	DC Gets X, CPU power and server template
	Member getz X CPU power and workstation template 

*/

// SystemConfig represents configuration for an individual system
type SystemConfig struct {
	Hostname           string `json:"hostname"`
	Domain             string `json:"domain"`
	IPAddr             string `json:"ipAddr"`
	ComputerRole string   `json:"ComputerRole"`
	IsChildDomainVariable string   `json:"isChildDomainVariable"`

}

// NetworkConfigFile manages a collection of system configurations
type NetworkConfigFile struct {
	Systems []SystemConfig `json:"systems"`
}

// NewNetworkConfigFile creates a new empty configuration
func NewNetworkConfigFile() *NetworkConfigFile {
	return &NetworkConfigFile{
		Systems: make([]SystemConfig, 0),
	}
}

// AddSystem adds a new system to the configuration
func (cfg *NetworkConfigFile) AddSystem(hostname, domain, ipAddr string, computerRole string, isChildDomainVariable string) {
	sys := SystemConfig{
		Hostname:           hostname,
		Domain:             domain,
		IPAddr:             ipAddr,
		ComputerRole:       computerRole,
		IsChildDomainVariable:          isChildDomainVariable,
	}
	cfg.Systems = append(cfg.Systems, sys)

}
		

// SaveToFile writes the configuration to a JSON file
func (cfg *NetworkConfigFile) SaveToFile(filename string) error {
	
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, data, 0644)
}



// Define the structure for DomainFilesMap to match the JSON structure
type DomainFilesMapJson struct {
	Domain   string `json:"Domain"`
	Datatype string `json:"Datatype"`
	Filename string `json:"Filename"`
	Filepath string `json:"Filepath"`
}

func getFilePathFromJson(jsonFilePath, domain, datatype string) (string, error) {
	// Read the JSON file content
	fileContent, err := ioutil.ReadFile(jsonFilePath)
	if err != nil {
		return "", fmt.Errorf("could not read file: %v", err)
	}

	// Parse the JSON content into a slice of DomainFilesMap
	var domainFiles []DomainFilesMapJson
	if err := json.Unmarshal(fileContent, &domainFiles); err != nil {
		return "", fmt.Errorf("could not unmarshal JSON: %v", err)
	}

	// Iterate through the domainFiles slice and find the matching domain and datatype
	for _, entry := range domainFiles {
		if entry.Domain == domain && entry.Datatype == datatype {
			return entry.Filepath, nil
		}
	}

	// If no matching entry is found, return an error
	return "", fmt.Errorf("no matching file found for domain: %s (Domain does not exist) and datatype: %s ", domain, datatype)
}

// IsChildDomain checks if a domain is a child domain
// Returns true if the domain has 3 or more parts (e.g., child.example.com)
// Returns false if the domain has only 2 parts (e.g., example.com)
func IsChildDomain(domainName string) bool {
	parts := strings.Split(domainName, ".")
	return len(parts) >= 3
}

//Configure variables before generating Ludus Config
func CoordinateLudusYMLVariables(filesMapPath string, aliveComputers *string, outputFile string, localRoles bool) {

	fmt.Println("Generating Ludus YML Config:")

	
	// Get working path containing bloohound folders 
	workingPath,_ := getAbsolutePath(strings.TrimSuffix(filesMapPath, "/filesMap.json"))
	// Get path for computerIPConfig file path
	computerIPConfigPath := workingPath + "/computerIPConfig.json"



	workingPathToZip := workingPath 
	bloodHoundZipPath := workingPath + "/BloodHound.zip"





	// Slice to hold computer configurations
	var computers []ComputerConfig

	var computersNoDomainMember []ComputerConfig_NoDomain

	// Create an empty DomainControllerTracker instance
	var domainTracker DomainControllerTracker	

	// Split the aliveComputers string into a slice of strings using the comma as a separator
	computersList := strings.Split(*aliveComputers, ",")

	ipLastOctet := 1
	//Loop through every computer 

	//Create computerIPMapping struct to store hostname, domain, IP address 

	// Create a new configuration
	computerIPConfig := NewNetworkConfigFile()


	// Iterate over the slice and print each FQDN
	for _, fqdn := range computersList {
		fqdn = strings.ToUpper(fqdn)
		fmt.Println("Creating config for " + fqdn)

		// Split the FQDN by dot (`.`)
		parts := strings.Split(fqdn, ".")

		// Extract hostname (first part) or DC01
		hostname := parts[0]
		isChild := false

		// Join the remaining parts for the domain name (starting from index 1)
		domainName := strings.Join(parts[1:], ".")
		if IsChildDomain(domainName) {
			

			//domainName := strings.Join(parts[2:], ".")

			isChild = true
		} 

		//Get file path for computers json file related to domain
		computersPath, err := getFilePathFromJson(filesMapPath, domainName, "Computer")
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		//fmt.Println(computersPath)

		// Parse the JSON file
		parsedComputers, err := parseComputersJson(computersPath)
		if err != nil {
			log.Fatalf("Error reading/parsing the file: %v", err)
		}

		DistinguishedName, err := GetComputerField(parsedComputers, fqdn, "DistinguishedName")
		if err != nil || DistinguishedName == "" {
			fmt.Println(fqdn + " does not exist")
			fmt.Println("exiting")
			os.Exit(1)
		}
		DistinguishedName, err = GetComputerField(parsedComputers, fqdn, "DistinguishedName")

		OperatingSystem, err := GetComputerField(parsedComputers, fqdn, "OperatingSystem")

		ramGB := 4
		ramMinGB := 2
		cpus := 2

		role := ""

		// Define all roles (you can dynamically add roles here)
		ansibleRoles := []string{
			"other.role.example", // Example additional role
		}

		// Define all role variables (you can dynamically add role variables here)
		ansibleRoleVars := map[string]interface{}{
			"another_role_variable":                   "some_value", // Example additional variable
		}

		// Perform type assertion to string because DistinghisnedName is type interface{}
		if dn, ok := DistinguishedName.(string); ok {
				// Check if DistinguishedName contains "Domain Controllers" and is child DC
				if strings.Contains(dn, "DOMAIN CONTROLLERS") && isChild == true {

					role = "member"
					domainTracker.DomainName = domainName
					domainTracker.HasPrimaryDC = true
					ramGB = 8
					ramMinGB = 4
					cpus = 4


						// Define all roles (you can dynamically add roles here)
						ansibleRoles = []string{
							"bagelByt3s.ludushound.upload_bloodhound_files",
							"bagelByt3s.ludushound.upload_ludushound_scripts",
							"bagelByt3s.ludushound.configure_dns_forwarders",
							"bagelByt3s.ludushound.promote_to_child_dc",
							"bagelByt3s.ludushound.disable_password_policy",
							"bagelByt3s.ludushound.create_domainadmin",
							"bagelByt3s.ludushound.create_bloodhound_users",
							"bagelByt3s.ludushound.create_bloodhound_computers",
							"bagelByt3s.ludushound.create_bloodhound_groups",
							"bagelByt3s.ludushound.create_bloodhound_gpos",
							"bagelByt3s.ludushound.create_bloodhound_containers",
							"bagelByt3s.ludushound.create_bloodhound_ous",
							"bagelByt3s.ludushound.configure_dns_forwarders_child_domains",
							"bagelByt3s.ludushound.create_bloodhound_domaintrusts",
							"bagelByt3s.ludushound.configure_relationship_domain_group_members",
							"bagelByt3s.ludushound.configure_relationship_local_group_members",
							"bagelByt3s.ludushound.configure_relationship_ou_members_computers",
							"bagelByt3s.ludushound.configure_relationship_ou_members_users",
							"bagelByt3s.ludushound.configure_relationship_ou_members_groups",
							"bagelByt3s.ludushound.configure_relationship_forcechangepassword",
							"bagelByt3s.ludushound.configure_relationship_dcsync",
							"bagelByt3s.ludushound.configure_relationship_sessions",
							"bagelByt3s.ludushound.configure_relationship_genericall",
							"bagelByt3s.ludushound.configure_relationship_genericwrite",
							"bagelByt3s.ludushound.configure_relationship_gplink",
							"bagelByt3s.ludushound.configure_constraineddelegation_user",
							"bagelByt3s.ludushound.disable_local_firewall",
	
							
						}
						// If user wants local roles just remove the prefix
						if localRoles {
							RemovePrefix(ansibleRoles)
						}

						// Split the FQDN by dot (`.`)
						parts := strings.Split(domainName, ".")

						childDomainName := domainName
						parentDomainName := strings.Join(parts[1:], ".")


						// Define all role variables (you can dynamically add role variables here)
						ansibleRoleVars = map[string]interface{}{
							"upload_bloodhound_files_sourcePath":      bloodHoundZipPath,
							"upload_bloodhound_files_destinationPath": "C:\\Windows\\Tasks\\LudusHound",
							"promote_to_child_dc_childfqdn": childDomainName,
							"promote_to_child_dc_parent_domain": parentDomainName,
							"ludushound_domain": childDomainName,
						}

					


		
					configVMName := hostname + "-" + strings.Replace(domainName, ".", "-", -1)
					configHostName := hostname

					template := GetTemplate(OperatingSystem.(string), hostname)
		

					// Call configVM for each VM to create the configuration
					computers = append(computers, configVM(
						configVMName, configHostName, template, 10, ipLastOctet, ramGB, ramMinGB, cpus,
						parentDomainName, role, ansibleRoles, ansibleRoleVars,
					))
					
					isChildDomainVariable := "True"
					fullIP := fmt.Sprintf("10.2.10.%d", ipLastOctet)
					computerIPConfig.AddSystem(configHostName, domainName, fullIP, "DC", isChildDomainVariable)
					


				} else	if strings.Contains(dn, "DOMAIN CONTROLLERS") && isChild == false {
					//fmt.Println(hostname + " is a Domain Controller")
	
					if isPrimaryRole(domainTracker, domainName) {

						role = "alt-dc"
						ramGB = 4
						ramMinGB = 4
						cpus = 4
	
					} else {
						role = "primary-dc"
						domainTracker.DomainName = domainName
						domainTracker.HasPrimaryDC = true
						ramGB = 8
						ramMinGB = 4
						cpus = 4
	
						// Define roles for DC (Not Child)
						ansibleRoles = []string{
							"bagelByt3s.ludushound.upload_bloodhound_files",
							"bagelByt3s.ludushound.upload_ludushound_scripts",
							"bagelByt3s.ludushound.configure_dns_forwarders",
							"bagelByt3s.ludushound.create_bloodhound_users",
							"bagelByt3s.ludushound.create_bloodhound_computers",
							"bagelByt3s.ludushound.create_bloodhound_groups",
							"bagelByt3s.ludushound.create_bloodhound_gpos",
							"bagelByt3s.ludushound.create_bloodhound_containers",
							"bagelByt3s.ludushound.create_bloodhound_ous",
							"bagelByt3s.ludushound.configure_dns_forwarders_child_domains",
							"bagelByt3s.ludushound.create_bloodhound_domaintrusts",
							"bagelByt3s.ludushound.configure_relationship_domain_group_members",
							"bagelByt3s.ludushound.configure_relationship_local_group_members",
							"bagelByt3s.ludushound.configure_relationship_ou_members_computers",
							"bagelByt3s.ludushound.configure_relationship_ou_members_users",
							"bagelByt3s.ludushound.configure_relationship_ou_members_groups",
							"bagelByt3s.ludushound.configure_relationship_forcechangepassword",
							"bagelByt3s.ludushound.configure_relationship_dcsync",
							"bagelByt3s.ludushound.configure_relationship_sessions",
							"bagelByt3s.ludushound.configure_relationship_genericall",
							"bagelByt3s.ludushound.configure_relationship_genericwrite",
							"bagelByt3s.ludushound.configure_relationship_gplink",
							"bagelByt3s.ludushound.configure_constraineddelegation_user",
							"bagelByt3s.ludushound.disable_local_firewall",
							
						}
						if localRoles {
							RemovePrefix(ansibleRoles)
						}
	
						// Define all role variables 
						ansibleRoleVars = map[string]interface{}{
							//"upload_bloodhound_files_sourcePath":      workingPath+"/",
							"upload_bloodhound_files_sourcePath":      bloodHoundZipPath,
							"upload_bloodhound_files_destinationPath": "C:\\Windows\\Tasks\\LudusHound",
							"ludushound_domain": domainName,
						}
	
					}
					
					//Variables that will be used in the Ludus config
					configVMName := hostname + "-" + strings.Replace(domainName, ".", "-", -1)
					configHostName := hostname
					template := GetTemplate(OperatingSystem.(string), hostname)
	
					// Call configVM for each VM to create the configuration
					computers = append(computers, configVM(
						configVMName, configHostName, template, 10, ipLastOctet, ramGB, ramMinGB, cpus,
						domainName, role, ansibleRoles, ansibleRoleVars,
					))
					
					fullIP := fmt.Sprintf("10.2.10.%d", ipLastOctet)
					isChildDomainVariable := "False"
					computerIPConfig.AddSystem(configHostName, domainName, fullIP, "DC", isChildDomainVariable)
	
	
				} else if !strings.Contains(dn, "DOMAIN CONTROLLERS") && isChild == false   {
				

					// Define all roles for non domain controllers
					ansibleRoles := []string{
						"bagelByt3s.ludushound.upload_bloodhound_files",
						"bagelByt3s.ludushound.upload_ludushound_scripts",
						"bagelByt3s.ludushound.install_rsat_tools",
						"bagelByt3s.ludushound.configure_relationship_local_group_members",
						"bagelByt3s.ludushound.configure_relationship_sessions",
						"bagelByt3s.ludushound.configure_unconstraineddelegation",
						"bagelByt3s.ludushound.disable_local_firewall",
					}
					if localRoles {
						RemovePrefix(ansibleRoles)
					}

					// Define all role variables 
					ansibleRoleVars := map[string]interface{}{
						"ludushound_domain": domainName,
						"upload_bloodhound_files_sourcePath":      bloodHoundZipPath,
						"upload_bloodhound_files_destinationPath": "C:\\Windows\\Tasks\\LudusHound",
					}

					configVMName := hostname + "-" + domainName 
					configHostName := hostname
					template := GetTemplate(OperatingSystem.(string), hostname)
					ramGB := 4
					ramMinGB := 2
					cpus := 2

					// Call configVM for each VM to create the configuration
					computers = append(computers, configVM(
						configVMName, configHostName, template, 10, ipLastOctet, ramGB, ramMinGB, cpus,
						domainName, "member", ansibleRoles, ansibleRoleVars,
					))
					fullIP := fmt.Sprintf("10.2.10.%d", ipLastOctet)
					computerIPConfig.AddSystem(configHostName, domainName, fullIP, "Member", "False")

					//Setup configuration for VM that is not a DC, but part of a child domain 
					//This will have to be joined manually - Ludus does not support child domains yet
				}	else if !strings.Contains(dn, "DOMAIN CONTROLLERS") && isChild == true   {

	
					childDomainName := domainName

					// Define all roles (you can dynamically add roles here)
					ansibleRoles := []string{
						"bagelByt3s.ludushound.upload_bloodhound_files",
						"bagelByt3s.ludushound.upload_ludushound_scripts",
						"bagelByt3s.ludushound.install_rsat_tools",
						"bagelByt3s.ludushound.join_nondomain_computer_to_domain",
						"bagelByt3s.ludushound.configure_relationship_local_group_members",
						"bagelByt3s.ludushound.configure_relationship_sessions",
						"bagelByt3s.ludushound.configure_unconstraineddelegation",
						"bagelByt3s.ludushound.disable_local_firewall",
					}
					if localRoles {
						RemovePrefix(ansibleRoles)
					}

					// Define all role variables (you can dynamically add role variables here)
					ansibleRoleVars := map[string]interface{}{
						"ludushound_domain": childDomainName,
						"upload_bloodhound_files_sourcePath":      bloodHoundZipPath,
						"upload_bloodhound_files_destinationPath": "C:\\Windows\\Tasks\\LudusHound",
						//"change_hostname_hostname": hostname,
				
					}

					configVMName := hostname + "-" + domainName 
					configHostName := hostname
					template := GetTemplate(OperatingSystem.(string), hostname)
					ramGB := 4
					ramMinGB := 2
					cpus := 2

					// Call configVM for each VM to create the configuration
					computersNoDomainMember = append(computersNoDomainMember, configVM_NoDomain(
						configVMName, configHostName, template, 10, ipLastOctet, ramGB, ramMinGB, cpus,
						domainName, "member", ansibleRoles, ansibleRoleVars,
					))
					fullIP := fmt.Sprintf("10.2.10.%d", ipLastOctet)
					computerIPConfig.AddSystem(configHostName, domainName, fullIP, "Member", "True")


					
				}

		} 

		ipLastOctet = ipLastOctet + 1 

	}

	// Save ComputerIPConfig to file
	 computerIPConfig.SaveToFile(computerIPConfigPath)

	err := zipFolder(workingPathToZip, bloodHoundZipPath)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		
		fmt.Println()
	}

		
	// Generate YAML and write it to a file
	fmt.Println("\nWriting Ludus Range to " + outputFile)

	// Ensure output directory exists
	dir := filepath.Dir(outputFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Fatalf("Error creating output directory: %v", err)
	}

	err = createYMLFile(computers, computersNoDomainMember, outputFile)
	if err != nil {
		log.Fatalf("Error generating YML file: %v", err)
	}		
	



}