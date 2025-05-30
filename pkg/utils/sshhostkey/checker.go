package sshhostkey

import (
	"bytes"
	"fmt"
	"github.com/jumpserver/koko/pkg/jms-sdk-go/model"
	"github.com/jumpserver/koko/pkg/logger"
	"github.com/jumpserver/koko/pkg/utils"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
)

type simpleHostKeyCallbackImpl struct {
	userConn     io.ReadWriter
	callGuard    CallbackCallGuard
	firstMessage atomic.Bool
}

func CreateHostKeyCallback(userConn io.ReadWriter, callGuard CallbackCallGuard) ssh.HostKeyCallback {
	if userConn == nil {
		userConn = &dummyReadWriter{}
	}
	if callGuard == nil {
		callGuard = &emptyCallbackCallGuard{}
	}
	cb := simpleHostKeyCallbackImpl{
		userConn:     userConn,
		callGuard:    callGuard,
		firstMessage: atomic.Bool{},
	}
	cb.firstMessage.Store(true)
	return cb.callback
}

func (cb *simpleHostKeyCallbackImpl) writeMessage(msg string) {
	if cb.firstMessage.CompareAndSwap(true, false) {
		utils.IgnoreErrWriteString(cb.userConn, "\r\n")
	}
	utils.IgnoreErrWriteString(cb.userConn, "[SSH] "+msg+"\r\n")
}

func (cb *simpleHostKeyCallbackImpl) readYesOrNo(prompt string) (bool, error) {
	vt := term.NewTerminal(cb.userConn, "")

	for i := 0; i < 5; i++ {
		utils.IgnoreErrWriteString(cb.userConn, "[SSH] "+prompt)
		line, err := vt.ReadLine()
		if err != nil {
			logger.Errorf("Get host key confirmation from user err: %s", err)
			return false, err
		}

		line = strings.TrimSpace(strings.ToLower(line))
		logger.Infof("Get host key confirmation from input for user %q", line)

		switch line {
		case "yes":
			return true, nil
		case "no":
			return false, nil
		}
	}

	logger.Errorf("No confirmation response has been made by user")
	return false, fmt.Errorf("no confirmation response has been made")
}

// userConn is a UserConnection interface, and we made all the implementations implement this interface
type connUserGetter interface {
	ConnUser() *model.User
}

func isSuperuser(userConn io.ReadWriter) bool {
	cug, ok := userConn.(connUserGetter)
	if !ok {
		return false
	}
	user := cug.ConnUser()
	return user != nil && user.IsSuperuser
}

func (cb *simpleHostKeyCallbackImpl) callback(hostname string, _ net.Addr, key ssh.PublicKey) error {
	cb.callGuard.OnEnter()
	defer cb.callGuard.OnExit()

	storeFilePath := filepath.Join(getHostKeyFolderPath(), "known_hosts")

	existingKeys, errorLineno, err := getHostKeys(storeFilePath, hostname)
	if err != nil {
		msg := fmt.Sprintf("Get host key for '%s' from '%s' failed: %v", hostname, storeFilePath, err)
		logger.Errorf("%s", msg)

		cb.writeMessage(msg)
		cb.writeMessage(fmt.Sprintf("Please contact the jumpserver administrator, fix the host fingerprint at %s:%d", storeFilePath, errorLineno))

		return fmt.Errorf("host key query failed")
	}

	receivedSha := ssh.FingerprintSHA256(key)
	receivedType := key.Type()

	if existingKeyItem, ok := existingKeys[receivedType]; ok {
		existingKey := existingKeyItem.key
		existingType := existingKey.Type()
		existingSha := ssh.FingerprintSHA256(existingKey)
		matched := bytes.Equal(key.Marshal(), existingKey.Marshal())

		if matched {
			logger.Infof("Host key matched for host %+q: %+q (%s)", hostname, receivedSha, receivedType)
			return nil
		}

		logger.Warnf("Host key mismatched for host '%s', expected '%s' (%s), received '%s' (%s)", hostname, existingSha, existingType, receivedSha, receivedType)

		cb.writeMessage(fmt.Sprintf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"))
		cb.writeMessage(fmt.Sprintf("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @"))
		cb.writeMessage(fmt.Sprintf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"))
		cb.writeMessage(fmt.Sprintf("The remote host key has been changed, or you are under man-in-the-middle attack attack!"))
		cb.writeMessage(fmt.Sprintf(""))
		cb.writeMessage(fmt.Sprintf("Host key mismatched for host '%s'", hostname))
		cb.writeMessage(fmt.Sprintf("Expected host key fingerprint: '%s' (%s)", existingSha, existingType))
		cb.writeMessage(fmt.Sprintf("Received host key fingerprint: '%s' (%s)", receivedSha, receivedType))

		if isSuperuser(cb.userConn) {
			cb.writeMessage("")
			userAllowed, err := cb.readYesOrNo("[ADMIN] Do you want to accept the new host key (yes/no)? ")
			if err != nil {
				return fmt.Errorf("host key verification failed: admin confirmation error: %v", err)
			}
			if !userAllowed {
				return fmt.Errorf("host key verification failed: host key mismatched")
			}
			cb.writeMessage(fmt.Sprintf("Warning: Permanently updated host key '%s' (%s) for '%s' to the list of known hosts", receivedSha, receivedType, hostname))

			if err := updateHostKey(storeFilePath, hostname, key); err != nil {
				logger.Errorf("Override host key to store %+q failed: %v", storeFilePath, err)
			}
			return nil
		} else {
			cb.writeMessage(fmt.Sprintf("Please contact the JumpServer administrator, to verify and fix the host fingerprint of host '%s' in %s:%d", hostname, storeFilePath, existingKeyItem.lineno))
			return fmt.Errorf("host key verification failed: host key mismatched")
		}
	} else {
		logger.Warnf("New host key for host %+q: %+q (%s)", hostname, receivedSha, receivedType)

		cb.writeMessage(fmt.Sprintf("The authenticity of host '%s' can't be established.", hostname))
		if len(existingKeys) > 0 {
			cb.writeMessage(fmt.Sprintf("Existing host key fingerprint:"))
			for _, existingKeyItem := range existingKeys {
				existingKey := existingKeyItem.key
				existingType := existingKey.Type()
				existingSha := ssh.FingerprintSHA256(existingKey)
				cb.writeMessage(fmt.Sprintf("    '%s' (%s)", existingSha, existingType))
			}
		}
		cb.writeMessage(fmt.Sprintf("Received host key fingerprint: '%s' (%s)", receivedSha, receivedType))

		if isSuperuser(cb.userConn) {
			userAllowed, err := cb.readYesOrNo("[ADMIN] Are you sure you want to continue connecting (yes/no)? ")
			if err != nil {
				return fmt.Errorf("host key verification failed: user confirmation error: %v", err)
			}
			if !userAllowed {
				return fmt.Errorf("host key verification failed: user said no")
			}

			cb.writeMessage(fmt.Sprintf("Warning: Permanently added host key '%s' (%s) for '%s' to the list of known hosts", receivedSha, receivedType, hostname))
			if err := addHostKey(storeFilePath, hostname, key); err != nil {
				logger.Errorf("Add host key to store %+q failed: %v", storeFilePath, err)
			}
			return nil
		} else {
			cb.writeMessage("Only JumpServer administrators are allowed to accept new host keys. Please contact the administrator to do so")
			return fmt.Errorf("host key verification failed: host key unrecognized")
		}
	}
}
