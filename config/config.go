package config

import (
	"crypto/tls"
	"fmt"
	"gopkg.in/ini.v1"
	"log"
	"os"
)

var Config *Configuration

type Configuration struct {
	Server    *ServerConfig
	TLSConfig *tls.Config
}

type ServerConfig struct {
	Host              string `ini:"HOST"`
	DebugMode         bool   `ini:"DEBUG_MODE"`
	Secret            string `ini:"SECRET"`
	AppId             string `ini:"APP_ID"`
	AppSecret         string `ini:"APP_SECRET"`
	VerificationToken string `ini:"VERIFICATION_TOKEN"`
	EncryptKey        string `ini:"ENCRYPT_KEY"`
}

func InitConfig() error {
	cfg, err := ini.Load("config.ini")
	if os.IsNotExist(err) {
		// use "global" location if file does not exist
		cfg, err = ini.Load("/etc/webhook2group.ini")
	}
	if err != nil {
		return err
	}

	s := &ServerConfig{
		Host:      "192.168.200.131:8001",
		DebugMode: false,
	}
	err = cfg.Section("server").MapTo(s)
	if err != nil {
		return err
	}

	if s.AppId == "" || s.AppSecret == "" {
		log.Fatalln("missing app_id or app_secret")
	}

	Config = &Configuration{
		Server: s,
	}

	return nil
}

func InitTLS() {
	cfg := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}
	cert, err := tls.LoadX509KeyPair("./server.crt", "./server.key")
	if err != nil {
		fmt.Println(err.Error())
	}
	cfg.Certificates = append(cfg.Certificates, cert)
	Config.TLSConfig = cfg
}
