package config

import (
	"gopkg.in/ini.v1"
	"log"
	"os"
)

var Config *Configuration

type Configuration struct {
	Server *ServerConfig
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
