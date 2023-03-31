package util

import (
	"log"
	"log/syslog"
)

func SetupLogging() {
	syslogger, err := syslog.New(syslog.LOG_INFO, "garm-provider-azure")
	if err != nil {
		return
	}

	log.SetOutput(syslogger)
}
