package Utils

import (
	"fmt"
	"os"
	"time"
	"path/filepath"
	"encoding/json"
	"io/ioutil"
	"archive/zip"
	"io"
)


// zipFolder takes an absolute path to a folder and creates a zip file at the specified location.
func zipFolder(sourceDir string, outputZip string) error {
	// Create the zip file
	zipFile, err := os.Create(outputZip)
	if err != nil {
		return fmt.Errorf("failed to create zip file: %w", err)
	}
	defer zipFile.Close()

	// Create a new zip writer
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Walk through the directory and add each file/folder to the zip
	err = filepath.Walk(sourceDir, func(file string, info os.FileInfo, err error) error {
		// Ignore any error walking the path
		if err != nil {
			return err
		}

		// Skip the source directory itself from being added to the zip file
		// We want the contents to be inside the zip, not the full path
		if file == sourceDir {
			return nil
		}

		// Get the relative path by removing the sourceDir prefix
		relPath, err := filepath.Rel(sourceDir, file)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}

		// If it's a directory, create the directory inside the zip
		if info.IsDir() {
			_, err := zipWriter.Create(relPath + "/") // Ensure it is a directory in the zip
			if err != nil {
				return fmt.Errorf("failed to create zip entry for directory %s: %w", file, err)
			}
			return nil
		}

		// It's a file, so open it and copy its contents into the zip
		fileToZip, err := os.Open(file)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %w", file, err)
		}
		defer fileToZip.Close()

		// Create a zip entry (file) inside the archive
		zipEntry, err := zipWriter.Create(relPath)
		if err != nil {
			return fmt.Errorf("failed to create zip entry for %s: %w", file, err)
		}

		// Copy the contents of the file into the zip entry
		_, err = io.Copy(zipEntry, fileToZip)
		if err != nil {
			return fmt.Errorf("failed to copy file %s into zip: %w", file, err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk through the source directory: %w", err)
	}

	return nil
}


// getAbsolutePath returns the absolute path for the given relative path.
func getAbsolutePath(relativePath string) (string, error) {
	// Get the absolute path using filepath.Abs
	absolutePath, err := filepath.Abs(relativePath)
	if err != nil {
		return "", fmt.Errorf("error getting absolute path: %w", err)
	}

	// Return the absolute path
	return absolutePath, nil
}


// writeFile saves the provided data to a specified file path.
func writeFile(filePath string, data interface{}) error {
	// Marshal the data to JSON with indentation for better readability
	file, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return fmt.Errorf("error marshalling data: %w", err)
	}

	// Write the JSON data to the specified file
	if err := ioutil.WriteFile(filePath, file, 0644); err != nil {
		return fmt.Errorf("error writing to file: %w", err)
	}

	return nil
}

// CreateUniqueFolder creates a folder in the specified base directory using the current date and time as the folder name.
func CreateUniqueFolder(baseDir string) (string, error) {
	// Get the current date and time
	currentTime := time.Now()

	// Format the time into a string that can be used as a folder name (e.g., "2025-01-10_14-30-15")
	folderName := currentTime.Format("2006-01-02_15-04-05")

	// Define the full folder path
	folderPath := baseDir + "/" + folderName

	// Create the directory
	err := os.Mkdir(folderPath, 0755)
	if err != nil {
		return "", fmt.Errorf("error creating folder: %w", err)
	}

	// Return the created folder path
	return folderPath, nil
}
// CreateDirIfNotExists checks if a directory exists, and if not, it creates it.
func CreateDirIfNotExists(dirPath string) error {
	// Check if the directory exists
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		// Directory does not exist, create it
		err := os.Mkdir(dirPath, 0755) // 0755 is the permission for the directory
		if err != nil {
			return fmt.Errorf("error creating directory: %w", err)
		}
		//fmt.Println("Directory created:", dirPath)
	} else {
		// Directory already exists
		//fmt.Println("Directory already exists:", dirPath)
		fmt.Printf("")
	}
	return nil
}