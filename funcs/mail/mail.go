package mail

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/smtp"
	"os"
	"github.com/joho/godotenv"
	"gopkg.in/gomail.v2"
)

var _ = godotenv.Load()

var (
	smtpHost       = os.Getenv("SMTP_HOST")
	smtpPort       = os.Getenv("SMTP_PORT")
	smtpUser       = os.Getenv("SMTP_USER")
	smtpPassword   = os.Getenv("SMTP_PASSWORD")
	smtpRecipient  = os.Getenv("SMTP_RECIPIENT")
)

func logErr(msg string, err error) {
	slog.Error(msg, "error", err)
}

func sendMail(to string, message *gomail.Message) error {
	var buffer bytes.Buffer

	if _, err := message.WriteTo(&buffer); err != nil {
		logErr("build email failed", err)
		return fmt.Errorf("build message error: %w", err)
	}

	addr := fmt.Sprintf("%s:%s", smtpHost, smtpPort)

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName: smtpHost,
	})
	if err != nil {
		logErr("tls connect failed", err)
		return fmt.Errorf("tls connect error: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, smtpHost)
	if err != nil {
		logErr("smtp client init failed", err)
		return fmt.Errorf("smtp client error: %w", err)
	}
	defer client.Quit()

	auth := smtp.PlainAuth("", smtpUser, smtpPassword, smtpHost)

	if err := client.Auth(auth); err != nil {
		logErr("smtp auth failed", err)
		return fmt.Errorf("auth error: %w", err)
	}

	if err := client.Mail(smtpUser); err != nil {
		logErr("smtp MAIL FROM failed", err)
		return fmt.Errorf("mail from error: %w", err)
	}

	if err := client.Rcpt(to); err != nil {
		logErr("smtp RCPT TO failed", err)
		return fmt.Errorf("rcpt error: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		logErr("smtp DATA failed", err)
		return fmt.Errorf("data error: %w", err)
	}

	if _, err := w.Write(buffer.Bytes()); err != nil {
		logErr("smtp write failed", err)
		_ = w.Close()
		return fmt.Errorf("write error: %w", err)
	}

	if err := w.Close(); err != nil {
		logErr("smtp close failed", err)
		return fmt.Errorf("close error: %w", err)
	}

	slog.Info("email sent successfully", "to", to)

	return nil
}

func SendMessageToAdmin(firstName, secondName, email, password string) error {
	message := gomail.NewMessage()

	message.SetHeader("From", fmt.Sprintf("MouseBook <%s>", smtpUser))
	message.SetHeader("To", smtpRecipient)
	message.SetHeader("Subject", "Зарегистрирован новый пользователь")

	message.SetBody("text/html", fmt.Sprintf(`
		<h1>NEW USER</h1>
		<p>Name: %s</p>
		<p>Surname: %s</p>
		<p>Email: %s</p>
		<p>Password: %s</p>
	`, firstName, secondName, email, password))

	return sendMail(smtpRecipient, message)
}

func SendMessageToUser(firstName, secondName, email, password string) error {
	message := gomail.NewMessage()

	message.SetHeader("From", fmt.Sprintf("MouseBook <%s>", smtpUser))
	message.SetHeader("To", email)
	message.SetHeader("Subject", "Регистрация в MouseBook")

	message.SetBody("text/html", fmt.Sprintf(`
		<h1>Данные для входа</h1>
		<p>Email: %s</p>
		<p>Password: %s</p>
	`, email, password))

	return sendMail(email, message)
}