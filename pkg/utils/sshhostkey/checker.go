package sshhostkey

import (
	"bytes"
	"fmt"
	"github.com/jumpserver/koko/pkg/logger"
	"golang.org/x/crypto/ssh"
	"net"
	"path/filepath"
)

type Messenger func(line string)

type simpleHostKeyCallbackImpl struct {
	messenger Messenger
}

func CreateHostKeyCallback(messenger Messenger) ssh.HostKeyCallback {
	if messenger == nil {
		messenger = func(line string) {}
	}
	cb := simpleHostKeyCallbackImpl{
		messenger: messenger,
	}
	return cb.callback
}

func (cb *simpleHostKeyCallbackImpl) callback(hostname string, _ net.Addr, key ssh.PublicKey) error {
	storeFilePath := filepath.Join(getHostKeyFolderPath(), "known_hosts")

	existingKey, lineno, err := getHostKey(storeFilePath, hostname)
	if err != nil {
		msg := fmt.Sprintf("Get host key for '%s' from '%s' failed: %v", hostname, storeFilePath, err)
		logger.Errorf("%s", msg)

		cb.messenger(msg)
		cb.messenger(fmt.Sprintf("Please contact the jumpserver administrator, fix the host fingerprint at %s:%d", storeFilePath, lineno))

		return fmt.Errorf("host key query failed")
	}

	receivedSha := ssh.FingerprintSHA256(key)
	receivedType := key.Type()

	if existingKey != nil {
		existingSha := ssh.FingerprintSHA256(existingKey)
		existingType := existingKey.Type()
		matched := bytes.Equal(key.Marshal(), existingKey.Marshal())

		if matched {
			logger.Infof("Host key matched for host '%s': '%s' (%s)", hostname, receivedSha, receivedType)
			return nil
		} else {
			logger.Warnf("Host key mismatched for host '%s', expected '%s' (%s), received '%s' (%s)", hostname, existingSha, existingType, receivedSha, receivedType)

			cb.messenger(fmt.Sprintf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"))
			cb.messenger(fmt.Sprintf("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @"))
			cb.messenger(fmt.Sprintf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"))
			cb.messenger(fmt.Sprintf("The remote host key has been changed, or you are under man-in-the-middle attack attack!"))
			cb.messenger(fmt.Sprintf(""))
			cb.messenger(fmt.Sprintf("Host key mismatched for host '%s'", hostname))
			cb.messenger(fmt.Sprintf("Expected host key fingerprint: '%s' (%s)", existingSha, existingType))
			cb.messenger(fmt.Sprintf("Received host key fingerprint: '%s' (%s)", receivedSha, receivedType))
			cb.messenger(fmt.Sprintf("Please contact the jumpserver administrator, verify and fix the host fingerprint of host '%s' in %s:%d", hostname, storeFilePath, lineno))

			return fmt.Errorf("host key verification failed")
		}
	} else {
		logger.Warnf("Host key missing for host '%s', remember it and let it pass: '%s' (%s)", hostname, receivedSha, receivedType)
		if err := addHostKey(storeFilePath, hostname, key); err != nil {
			logger.Errorf("Add host key store to '%s' failed: %v", storeFilePath, err)
		}

		cb.messenger(fmt.Sprintf("Warning: Permanently added host key '%s' (%s) for '%s' to the list of known hosts", receivedSha, receivedType, hostname))
		return nil
	}
}
