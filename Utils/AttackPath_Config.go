package Utils
// Package to create Ludus config if given attackpath.json
import (
	"encoding/json"
	"fmt"
	"strings"
	"io/ioutil"
	"path/filepath"
)

// Struct for VM Config
type LudusVM struct {
	VMName       string `yaml:"vm_name"`
	Hostname     string `yaml:"hostname"`
	Template     string `yaml:"template"`
	VLAN         int    `yaml:"vlan"`
	IPLastOctet  int    `yaml:"ip_last_octet"`
	RAMGB        int    `yaml:"ram_gb"`
	RAMMinGB     int    `yaml:"ram_min_gb"`
	CPUs         int    `yaml:"cpus"`
	Windows      struct {
		Sysprep bool `yaml:"sysprep"`
	} `yaml:"windows"`
	Domain struct {
		FQDN string `yaml:"fqdn"`
		Role string `yaml:"role"`
	} `yaml:"domain"`
	Roles    []string          `yaml:"roles"`
	RoleVars map[string]string `yaml:"role_vars"`
}

type LudusConfig_AttackPath struct {
	Ludus []LudusVM `yaml:"ludus"`
}

/* Exporting Bloodhound Attackpath.json sometimes contains a "Data -> Node or just Node" structure. 
AttackPathNode and AttackPathData are used to handle both types
*/
type AttackPathNode struct {
	Label        string `json:"label"`
	Kind         string `json:"kind"`
	ObjectId     string `json:"objectId"`
	IsTierZero   bool   `json:"isTierZero"`
	IsOwnedObject bool   `json:"isOwnedObject"`
	LastSeen     string `json:"lastSeen"`
}

type AttackPathData struct {
	// For direct structure {"nodes": {...}, "edges": [...]}
	Nodes map[string]AttackPathNode `json:"nodes"`
	Edges []interface{} `json:"edges"`
	
	// For nested structure {"data": {"nodes": {...}, "edges": [...]}}
	Data struct {
		Nodes map[string]AttackPathNode `json:"nodes"`
		Edges []interface{} `json:"edges"`
	} `json:"data"`
}

// Takes the Domain Controller argument and parses out the domain
// This domain will be the domain of the lab 
func ParseDomainController(dcFQDN string) (string, string, error) {
	parts := strings.Split(dcFQDN, ".")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("DomainController must be in format hostname.domain.tld")
	}
	
	hostname := strings.ToUpper(parts[0])
	domain := strings.ToUpper(strings.Join(parts[1:], "."))
	
	return hostname, domain, nil
}

func WriteLudusConfig_AttackPath(outputPath string, yamlContent string) error {
	return ioutil.WriteFile(outputPath, []byte(yamlContent), 0644)
}

func CreateLudusConfig_AttackPath(dcFQDN, attackPath string) string {
	return fmt.Sprintf("Ludus config for DC: %s with attack path: %s", dcFQDN, attackPath)
}

func GenerateLudusYAMLWithAttackPath(dcHostname, domain, attackPathFile string) (string, error) {
	// Read the attack path file
	data, err := ioutil.ReadFile(attackPathFile)
	if err != nil {
		return "", fmt.Errorf("failed to read attack path file: %v", err)
	}
	
	// Get the absolute path of the attack path file
	absAttackPath, err := filepath.Abs(attackPathFile)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %v", err)
	}
	
	// Parse the JSON
	var attackPath AttackPathData
	err = json.Unmarshal(data, &attackPath)
	if err != nil {
		return "", fmt.Errorf("failed to parse attack path JSON: %v", err)
	}
	
	// Start building the YAML configuration
	var vmConfigs []string
	
	// Add DC configuration first
	dcConfig := fmt.Sprintf(`  - vm_name: %s-%s
    hostname: %s
    template: win2016-server-x64-template
    vlan: 10
    ip_last_octet: 1
    ram_gb: 8
    ram_min_gb: 4
    cpus: 4
    windows:
      sysprep: true
    domain:
      fqdn: %s
      role: primary-dc
    roles:
      - bagelByt3s.ludushound.attackpath_upload_attackjson
      - bagelByt3s.ludushound.attackpath_upload_scripts
      - bagelByt3s.ludushound.attackpath_configure_domain
      - bagelByt3s.ludushound.attackpath_configure_localgroup
      - bagelByt3s.ludushound.disable_local_firewall
    role_vars:
      ludushound_domain: %s
      ludushound_attackpath: %s`,
		dcHostname, strings.ReplaceAll(domain, ".", "-"),
		dcHostname,
		domain,
		domain,
		absAttackPath)
	
	vmConfigs = append(vmConfigs, dcConfig)
	
	// Process computer nodes from attack path
	ipLastOctet := 2
	
	// Determine which nodes map to use based on the structure
	var nodesMap map[string]AttackPathNode
	if len(attackPath.Nodes) > 0 {
		// Direct structure
		nodesMap = attackPath.Nodes
	} else {
		// Nested structure
		nodesMap = attackPath.Data.Nodes
	}
	
	for _, node := range nodesMap {
		if node.Kind == "Computer" {
			
			var nodehostname string
			var addComputer bool
			
			// Check if the label contains a domain
			parts := strings.Split(node.Label, ".")
			if len(parts) > 1 {
				// Computer has FQDN format
				nodehostname = parts[0]
				nodeDomain := strings.Join(parts[1:], ".")
				
				// Only add computers from the same domain
				if strings.EqualFold(nodeDomain, domain) {
					addComputer = true
				}
			} else {
				// Computer has only hostname
				nodehostname = parts[0]
				// Assume it's part of the domain we're building
				addComputer = true
			}
			//Only process if the nodehostname is not the same as DCHostname
			if strings.ToLower(nodehostname) != strings.ToLower(dcHostname) {
				
			
			
			
			if addComputer {
				computerConfig := fmt.Sprintf(`  - vm_name: %s-%s
    hostname: %s
    template: win2016-server-x64-template
    vlan: 10
    ip_last_octet: %d
    ram_gb: 8
    ram_min_gb: 4
    cpus: 4
    windows:
      sysprep: true
    domain:
      fqdn: %s
      role: member
    roles:
      - bagelByt3s.ludushound.attackpath_upload_attackjson
      - bagelByt3s.ludushound.attackpath_upload_scripts
      - bagelByt3s.ludushound.install_rsat_tools
      - bagelByt3s.ludushound.attackpath_configure_localgroup
      - bagelByt3s.ludushound.attackpath_configure_session
      - bagelByt3s.ludushound.disable_local_firewall
    role_vars:
      ludushound_domain: %s
      ludushound_attackpath: %s`,
					nodehostname, strings.ReplaceAll(domain, ".", "-"),
					nodehostname,
					ipLastOctet,
					domain,
					domain,
					absAttackPath)
				
				vmConfigs = append(vmConfigs, computerConfig)
				ipLastOctet++
			}
		}
	}
}
	
	// Combine all VM configurations
	yamlContent := "ludus:\n" + strings.Join(vmConfigs, "\n")
	yamlContent = yamlContent + "\n"
	return yamlContent, nil
}