package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/robfig/cron"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	harbor_go "hyperregistry-oidc-webhook/pkg/habor-go"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var (
	logger    *zap.Logger
	harborApi *harbor_go.RestClient
)

func main() {
	// get harbor using environment variables.
	harborURL := os.Getenv("harborURL")
	harborUser := os.Getenv("harborUser")
	harborPassword := os.Getenv("harborPassword")
	// get kafka using environment variables.
	kafkaURL := os.Getenv("kafkaURL")
	topic := os.Getenv("topic")

	var err error
	if logger, err = newDailyRotateLogger("access.log"); err != nil {
		os.Exit(1)
	}
	defer logger.Sync()

	cfg := &harbor_go.Config{
		ServerUrl: harborURL,
		User:      strings.TrimSpace(harborUser),
		Password:  strings.TrimSpace(harborPassword),
	}
	harborApi = harbor_go.NewRestClient(cfg)

	dialer := &kafka.Dialer{
		Timeout:   10 * time.Second,
		DualStack: true,
		TLS: &tls.Config{
			//Certificates:                nil,
			//RootCAs:                     nil,
			InsecureSkipVerify: true,
		},
	}

	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:   []string{kafkaURL},
		Topic:     topic,
		Partition: 0,
		MinBytes:  10e3, // 10KB
		MaxBytes:  10e6, // 10MB
		Dialer:    dialer,
	})

	setupSigHandler(func() {
		logger.Info("Catch up signal. Start graceful shutdown...")
		err := r.Close()
		if err != nil {
			logger.Error(err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	})

	for {
		m, err := r.ReadMessage(context.Background())
		if err != nil {
			logger.Error(err.Error())
			break
		}

		value := &AuthEvent{}
		err = json.Unmarshal(m.Value, &value)
		if err != nil {
			logger.Error(err.Error())
			continue
		}

		switch value.MsgType {
		case "LOGIN":
			logger.Info(string(m.Value), zap.Int64("offset", m.Offset), zap.ByteString("key", m.Key))
			if err = handleLogin(value); err != nil {
				logger.Error(err.Error())
			}
		case "LOGOUT":
			if err = handleLogout(value); err != nil {
				logger.Error(err.Error())
			}
		case "CODE_TO_TOKEN":
			if err = handleIssueToken(value); err != nil {
				logger.Error(err.Error())
			}
		case "USER_INFO_REQUEST":
			if err = handleUserInfo(value); err != nil {
				logger.Error(err.Error())
			}
		case "LOGIN_ERROR":
			if err = handleLoginFail(value); err != nil {
				logger.Error(err.Error())
			}
		case "USER_DELETE":
			if err = handleDeleteUser(value); err != nil {
				logger.Error(err.Error())
			}
		}
	}
}

func setupSigHandler(f func()) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		f()
	}()
}

type AuthEvent struct {
	MsgType      string        `json:"type"`
	ClientId     string        `json:"clientId"`
	RealmId      string        `json:"realmId"`
	SessionId    string        `json:"sessionId"`
	IPAddress    string        `json:"IPAddress"`
	UserId       string        `json:"userId"`
	UserName     string        `json:"userName"`
	CreationTime time.Duration `json:"time"`
	Details      AuthDetail    `json:"details"`
}

type AuthDetail struct {
	Method      string `json:"auth_method"`
	RedirectURI string `json:"redirect_uri"`
	Consent     string `json:"consent"`
	CodeId      string `json:"code_id"`
	Username    string `json:"username"`
}

func handleLogin(e *AuthEvent) error {
	//logger.Info("handle login...")

	projectName := strings.Split(e.UserName, "@")[0]
	project, err := harborApi.GetProject(projectName)
	if err != nil {
		if harbor_go.IsNotFound(err) {
			logger.Info("project not found on server. create new one...", zap.String("project", projectName))
			isCreated, err := harborApi.NewProject(projectName, false)
			if err != nil || !isCreated {
				return err
			}
		}
	}
	logger.Info("[GET] project", zap.String("name", projectName), zap.Int("id", project.ProjectId))

	ok, err := harborApi.AddProjectMember(project.ProjectId, e.UserName, 1)
	if err != nil || !ok {
		return err
	}
	logger.Info("[ADD] project member", zap.String("project", project.Name), zap.String("username", e.UserName))

	return nil
}

func handleLogout(e *AuthEvent) error {
	//logger.Info("handle logout")
	return nil
}

func handleIssueToken(e *AuthEvent) error {
	//logger.Info("handle IssueToken")
	return nil
}

func handleUserInfo(e *AuthEvent) error {
	//logger.Info("handle UserInfo")
	return nil
}

func handleLoginFail(e *AuthEvent) error {
	//logger.Info("handle LoginFail")
	return nil
}
func handleDeleteUser(e *AuthEvent) error {
	//logger.Info("handle DeleteUser")
	return nil
}

func newDailyRotateLogger(logpath string) (*zap.Logger, error) {
	ll := &lumberjack.Logger{
		Filename: logpath,
		MaxSize:  500, // megabytes
		//MaxAge:     90, // days
	}

	cronJob := cron.New()
	if err := cronJob.AddFunc("@daily", func() {
		if err := ll.Rotate(); err != nil {
			fmt.Println("failed to rotate log.")
		}
	}); err != nil {
		fmt.Println("failed to rotate log file")
		os.Exit(1)
	}
	defer cronJob.Start()

	w := zapcore.AddSync(io.MultiWriter(ll, os.Stdout))
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		w,
		zap.InfoLevel,
	)
	return zap.New(core), nil
}
