package sshhostkey

import (
	"bytes"
	"fmt"
	"github.com/jumpserver/koko/pkg/logger"
	"golang.org/x/crypto/ssh"
	"net"
	"path/filepath"
)

func CreateHostKeyCallback() ssh.HostKeyCallback {
	return simpleHostKeyCallback
}

func simpleHostKeyCallback(hostname string, _ net.Addr, key ssh.PublicKey) error {
	storeFilePath := filepath.Join(getHostKeyFolderPath(), "known_hosts")

	existingKey, err := getHostKey(storeFilePath, hostname)
	if err != nil {
		logger.Errorf("Get host key for '%s' from '%s' failed: %v", hostname, storeFilePath, err)
		return err
	}

	if existingKey != nil {
		matched := bytes.Equal(key.Marshal(), existingKey.Marshal())
		if matched {
			logger.Infof("Host key matched for host '%s': %s", hostname, ssh.FingerprintSHA256(key))
			return nil
		} else {
			msg := fmt.Sprintf("host key mismatched for host '%s', expected %s, found %s", hostname, ssh.FingerprintSHA256(existingKey), ssh.FingerprintSHA256(key))
			logger.Warnf("%s", msg)
			return fmt.Errorf("%s. Please let the admin verify the host fingerprint of host '%s' in file '%s'", msg, hostname, storeFilePath)
		}
	} else {
		logger.Warnf("Host key missing for host '%s', remember it and let it pass: %s", hostname, ssh.FingerprintSHA256(key))
		if err := addHostKey(storeFilePath, hostname, key); err != nil {
			logger.Errorf("Add host key store to '%s' failed: %v", storeFilePath, err)
		}
		return nil
	}
}
