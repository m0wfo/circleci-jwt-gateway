package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/dgrijalva/jwt-go"
)

type JobInfo struct {
	User        string
	Repo        string
	BuildNumber int `json:"build_number"`
	Revision    string
}

type CircleJob struct {
	VcsRevision string
	Lifecycle   string
}

func getSecret() string {
	secretName := os.Getenv("CIRCLE_TOKEN_NAME")
	if secretName == "" {
		log.Panic("No CIRCLE_TOKEN_NAME env var set")
	}

	region := "eu-west-1"

	//Create a Secrets Manager client
	svc := secretsmanager.New(session.New(),
		aws.NewConfig().WithRegion(region))
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"), // VersionStage defaults to AWSCURRENT if unspecified
	}

	result, err := svc.GetSecretValue(input)
	if err != nil {
		log.Panic(err)
	}

	// Decrypts secret using the associated KMS CMK.
	// Depending on whether the secret is a string or binary, one of these fields will be populated.
	if result.SecretString != nil {
		return *result.SecretString
	} else {
		decodedBinarySecretBytes := make([]byte, base64.StdEncoding.DecodedLen(len(result.SecretBinary)))
		len, err := base64.StdEncoding.Decode(decodedBinarySecretBytes, result.SecretBinary)
		if err != nil {
			log.Panic(err)
		}
		return string(decodedBinarySecretBytes[:len])
	}
}

func getSecretKey(keyName string) string {
	secretKvps := getSecret()
	var tokenKeys map[string]string
	err := json.Unmarshal([]byte(secretKvps), &tokenKeys)
	handleError(err)
	return tokenKeys[keyName]
}

func createToken() (string, error) {
	claims := jwt.MapClaims{}
	claims["aud"] = "cicd"
	claims["exp"] = time.Now().Add(time.Minute * 10).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signingKey := getSecretKey("JWT_KEY")
	return token.SignedString([]byte(signingKey))
}

func handleError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func HandleRequest(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	data, err := base64.StdEncoding.DecodeString(request.Body)
	handleError(err)
	var info JobInfo
	err = json.Unmarshal([]byte(data), &info)
	handleError(err)
	circleToken := getSecretKey("CIRCLE_TOKEN")

	url := "https://circleci.com/api/v1.1/project/gh/" + info.User + "/" + info.Repo + "/" + strconv.Itoa(info.BuildNumber) + "?circle-token=" + circleToken
	log.Print(url)
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("Accept", "application/json")
	handleError(err)

	client := &http.Client{}
	resp, err := client.Do(req)
	handleError(err)
	defer resp.Body.Close()

	var job CircleJob
	err = json.NewDecoder(resp.Body).Decode(&job)
	handleError(err)

	var body string
	var sc int
	if resp.StatusCode == 200 {
		if job.Lifecycle == "finished" {
			body = "Job has already finished"
			sc = 400
		} else {
			if job.VcsRevision != info.Revision {
				sc = 400
				body = "Bad revision"
			} else {
				body, err = createToken()
				handleError(err)
				sc = 200
			}
		}
	} else {
		body = "Bad request"
		sc = resp.StatusCode
	}

	return events.APIGatewayProxyResponse{Body: body, StatusCode: sc}, nil
}

func main() {
	lambda.Start(HandleRequest)
}
