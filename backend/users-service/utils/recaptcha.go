package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
)

type CaptchaResponse struct {
	Success     bool     `json:"success"`
	ChallengeTs string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes,omitempty"`
}

func VerifyCaptcha(token string) (bool, error) {
	secretKey := os.Getenv("SECRET_KEY")
	if secretKey == "" {
		return false, fmt.Errorf("SECRET_KEY is not set in environment variables")
	}

	data := url.Values{}
	data.Set("secret", secretKey)
	data.Set("response", token)

	resp, err := http.PostForm("https://www.google.com/recaptcha/api/siteverify", data)
	if err != nil {
		return false, fmt.Errorf("error sending request to Google API: %v", err)
	}
	defer resp.Body.Close()

	var captchaResp CaptchaResponse
	if err := json.NewDecoder(resp.Body).Decode(&captchaResp); err != nil {
		return false, fmt.Errorf("error decoding Google API response: %v", err)
	}

	return captchaResp.Success, nil
}
