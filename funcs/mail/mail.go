package mail

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/smtp"
	"os"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
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
	domain         = os.Getenv("DOMAIN")
	dkimSelector   = os.Getenv("DKIM_SELECTOR")
	dkimPrivateKey = os.Getenv("DKIM_PRIVATE_KEY")
)

func logErr(msg string, err error) {
	slog.Error(msg, "error", err)
}

func signDKIM(data []byte) ([]byte, error) {
	pemStr := strings.ReplaceAll(dkimPrivateKey, "\\n", "\n")

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		err := fmt.Errorf("invalid PEM key")
		logErr("dkim decode failed", err)
		return nil, err
	}

	var rsaKey *rsa.PrivateKey

	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		var ok bool
		rsaKey, ok = keyAny.(*rsa.PrivateKey)
		if !ok {
			err := fmt.Errorf("not RSA private key (PKCS8)")
			logErr("dkim key type error", err)
			return nil, err
		}
	} else {
		rsaKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			logErr("dkim parse private key failed", err)
			return nil, fmt.Errorf("parse private key failed: %w", err)
		}
	}

	options := &dkim.SignOptions{
		Domain:   domain,
		Selector: dkimSelector,
		Signer:   rsaKey,
	}

	var out bytes.Buffer
	if err := dkim.Sign(&out, bytes.NewReader(data), options); err != nil {
		logErr("dkim signing failed", err)
		return nil, fmt.Errorf("dkim sign error: %w", err)
	}

	return out.Bytes(), nil
}

func sendSignedMail(to string, message *gomail.Message) error {
	var buffer bytes.Buffer

	if _, err := message.WriteTo(&buffer); err != nil {
		logErr("build email failed", err)
		return fmt.Errorf("build message error: %w", err)
	}

	signed, err := signDKIM(buffer.Bytes())
	if err != nil {
		logErr("dkim step failed", err)
		return fmt.Errorf("dkim error: %w", err)
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

	if _, err := w.Write(signed); err != nil {
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

	return sendSignedMail(smtpRecipient, message)
}

func SendMessageToUser(email, password string) error {
	message := gomail.NewMessage()

	message.SetHeader("From", fmt.Sprintf("MouseBook <%s>", smtpUser))
	message.SetHeader("To", email)
	message.SetHeader("Subject", "Регистрация в MouseBook")

	message.SetBody("text/html", fmt.Sprintf(`
		<h1>Данные для входа</h1>
		<p>Email: %s</p>
		<p>Password: %s</p>
	`, email, password))

	return sendSignedMail(email, message)
}
