package services

import (
	"bufio"
	"os"
)

// LoadBlackList učitava lozinke iz fajla u mapu
func LoadBlackList(filePath string) (map[string]bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	blackList := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		blackList[scanner.Text()] = true
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return blackList, nil
}
