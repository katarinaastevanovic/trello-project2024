package utils

import (
	"fmt"
	"net/smtp"
	"os"
)

// SendEmail šalje email na zadatu adresu sa naslovom i sadržajem koristeći net/smtp biblioteku
func SendEmail(to, subject, body string) error {
	// Email podaci
	from := "trixtix9@gmail.com"
	password := os.Getenv("EMAIL_PASSWORD")

	// SMTP server konfiguracija
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	// Provera da li je postavljena lozinka
	if password == "" {
		return fmt.Errorf("EMAIL_PASSWORD nije postavljena")
	}

	// Priprema sadržaja poruke
	message := []byte("Subject: " + subject + "\r\n" +
		"From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Content-Type: text/html; charset=\"UTF-8\"\r\n\r\n" +
		body + "\r\n")

	// Autentifikacija sa SMTP serverom
	auth := smtp.PlainAuth("", from, password, smtpHost)

	// Slanje emaila
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, message)
	if err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}

	return nil
}

// SendRegistrationEmail šalje email za potvrdu registracije
func SendRegistrationEmail(to, token string) error {
	subject := "Confirm your registration"
	confirmationLink := fmt.Sprintf("https://localhost:4200/confirm-email?token=%s", token)
	body := fmt.Sprintf(`
		<h3>Welcome!</h3>
		<p>Please confirm your registration by clicking the link below:</p>
		<a href="%s">Confirm Email</a>
	`, confirmationLink)

	return SendEmail(to, subject, body)
}

// SendPasswordResetEmail šalje email sa linkom za resetovanje lozinke
func SendPasswordResetEmail(to, token string) error {
	subject := "Reset your password"
	resetLink := fmt.Sprintf("https://localhost:4200/reset-password?token=%s", token)
	body := fmt.Sprintf(`
		<h3>Password Reset Request</h3>
		<p>Click the link below to reset your password:</p>
		<a href="%s">Reset Password</a>
	`, resetLink)

	return SendEmail(to, subject, body)
}

// SendLoginNotification šalje email prilikom prijave (opciono)
func SendLoginNotification(to string) error {
	subject := "Login Notification"
	body := `
		<h3>Login Alert</h3>
		<p>Your account was just accessed. If this wasn't you, please secure your account.</p>
	`

	return SendEmail(to, subject, body)
}
