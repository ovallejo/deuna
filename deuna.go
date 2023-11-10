package deuna

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/brianvoe/gofakeit/v6"
	_ "github.com/jackc/pgx/v5/stdlib"
	"go.k6.io/k6/js/modules"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	LOG_GROUP_NAME   = "deuna-tl-otp-service-log-group"
	PREFIX_LOG_GROUP = "deuna-tl-otp"
)

type DynamicData struct {
	RequestID string `json:"requestId"`
	OTP       int    `json:"otp"`
}

type Metadata struct {
	PushToken   string   `json:"pushToken"`
	PhoneNumber string   `json:"phoneNumber"`
	Email       []string `json:"email"`
}

type TrackingID struct {
	TemplateKey  string      `json:"templateKey"`
	DynamicData  DynamicData `json:"dynamicData"`
	Metadata     Metadata    `json:"metadata"`
	TrackingData string      `json:"trackingId"`
	ActionEvent  string      `json:"actionEvent"`
}

type Context struct {
	Level      string `json:"level"`
	Timestamp  string `json:"timestamp"`
	PID        int    `json:"pid"`
	Hostname   string `json:"hostname"`
	Message    string `json:"message"`
	TrackingID string `json:"trackingId"`
}

func init() {
	modules.Register("k6/x/deuna", new(Deuna))
}

type Deuna struct{}

func (*Deuna) Encriptar(message, publicKeyNoPEM string) string {
	// Decodificar la clave pública PEM desde una cadena
	block, _ := base64.StdEncoding.DecodeString(publicKeyNoPEM)

	// Parsear la clave pública en una estructura RSA
	publicKey, _ := x509.ParsePKIXPublicKey(block)

	// Convertir la clave a su tipo original (rsa.PublicKey)
	rsaPublicKey, _ := publicKey.(*rsa.PublicKey)

	// Encriptar el mensaje con la clave pública
	encryptedMessageBytes, _ := rsa.EncryptOAEP(
		sha1.New(),
		rand.Reader,
		rsaPublicKey,
		[]byte(message),
		[]byte(""),
	)

	return base64.StdEncoding.EncodeToString(encryptedMessageBytes)
}
func (*Deuna) Nombre() string {
	return gofakeit.FirstName()
}

func (*Deuna) Apellido() string {
	return gofakeit.LastName()
}
func (*Deuna) Usuario() string {
	return gofakeit.Username()
}

func (*Deuna) Clave(tam int) string {
	return gofakeit.Password(true, true, true, false, false, tam)
}

func (*Deuna) Ciudad() string {
	return gofakeit.Address().City
}

func (*Deuna) Calle() string {
	return gofakeit.Address().Street
}

func (*Deuna) GenerarCedula() string {
	cedulaBase, _ := rand.Int(rand.Reader, big.NewInt(1000000000))
	total := 0
	for i := 0; i < 9; i++ {
		digit, _ := strconv.Atoi(string(cedulaBase.String()[i]))
		if i%2 == 0 {
			doubled := digit * 2
			if doubled > 9 {
				total += doubled - 9
			} else {
				total += doubled
			}
		} else {
			total += digit
		}
	}
	lastDigit := strconv.Itoa((10 - (total % 10)) % 10)
	return cedulaBase.String() + lastDigit
}

func (*Deuna) GetOtp(phoneNumber string) string {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		Config:            aws.Config{Region: aws.String("us-east-1")},
		SharedConfigState: session.SharedConfigEnable,
	}))

	svc := cloudwatchlogs.New(sess)

	currentTime := time.Now()
	endTime := currentTime
	startTime := currentTime.Add(-5 * time.Minute)

	params := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName:        aws.String(LOG_GROUP_NAME),
		LogStreamNamePrefix: aws.String(PREFIX_LOG_GROUP),
		StartTime:           aws.Int64(startTime.Unix() * 1000),
		EndTime:             aws.Int64(endTime.Unix() * 1000),
	}

	result, err := svc.FilterLogEvents(params)
	if err != nil {
		return ""
	}

	var listaOtps []string

	for _, event := range result.Events {
		message := aws.StringValue(event.Message)
		if strings.Contains(message, phoneNumber) {
			listaOtps = append(listaOtps, message)
		}
	}

	if len(listaOtps) == 0 {
		return "123456"
	}

	tramaOTP := listaOtps[len(listaOtps)-1]
	var context Context
	if err := json.Unmarshal([]byte(tramaOTP), &context); err != nil {
		return strconv.Itoa(0)
	}

	var trackingID TrackingID
	if err := json.Unmarshal([]byte(context.TrackingID), &trackingID); err != nil {
		return strconv.Itoa(0)
	}

	return strconv.Itoa(trackingID.DynamicData.OTP)

}

func (*Deuna) ConnectToDB(query string, args ...interface{}) bool {
	db, err := sql.Open("pgx", os.Getenv("PG_HOST"))
	if err != nil {
		fmt.Printf("Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {
			fmt.Printf("Error closing the database connection: %v\n", err)
		}
	}(db)

	_, err = db.Exec(query, args...)
	if err != nil {
		log.Fatal(err)
		return false
	}
	return true
}
