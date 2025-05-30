package sshhostkey

import (
	"bufio"
	"fmt"
	"github.com/jumpserver/koko/pkg/config"
	"golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var hostKeyStoreMutex sync.RWMutex

func closeFileIgnoreError(f *os.File) {
	_ = f.Close()
}

type HostKeyMapItem struct {
	key    ssh.PublicKey
	lineno int
}

type HostKeyMap = map[string]HostKeyMapItem // key type -> key item

func getHostKeys(filePath, hostname string) (HostKeyMap, int, error) {
	hostKeyStoreMutex.RLock()
	defer hostKeyStoreMutex.RUnlock()

	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	defer closeFileIgnoreError(file)

	hostKeyMap := make(map[string]HostKeyMapItem)

	scanner := bufio.NewScanner(file)
	lineno := 0
	for scanner.Scan() {
		lineno++
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) != 3 {
			continue // Skip lines that don't have three fields.
		}

		host := fields[0]
		if host != hostname {
			continue
		}

		key, _, _, _, err := ssh.ParseAuthorizedKey(scanner.Bytes())
		if err != nil {
			return nil, lineno, fmt.Errorf("invalid public key for host '%s' at line %d: %v", host, lineno, err)
		}

		hostKeyMap[key.Type()] = HostKeyMapItem{
			key:    key,
			lineno: lineno,
		}
	}
	return hostKeyMap, 0, nil
}

func addHostKeyNoLock(filePath, hostname string, key ssh.PublicKey) error {
	if err := config.EnsureDirExist(filepath.Dir(filePath)); err != nil {
		return err
	}

	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer closeFileIgnoreError(file)

	_, err = file.WriteString(fmt.Sprintf("%s %s", hostname, ssh.MarshalAuthorizedKey(key)))
	return err
}

func addHostKey(filePath, hostname string, key ssh.PublicKey) error {
	hostKeyStoreMutex.Lock()
	defer hostKeyStoreMutex.Unlock()
	return addHostKeyNoLock(filePath, hostname, key)
}

func updateHostKey(filePath, hostname string, key ssh.PublicKey) error {
	hostKeyStoreMutex.Lock()
	defer hostKeyStoreMutex.Unlock()

	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return addHostKeyNoLock(filePath, hostname, key)
		}
		return fmt.Errorf("failed to open host key file %+q: %v", filePath, err)
	}
	defer closeFileIgnoreError(file)

	tmpFilePath := filePath + ".tmp"
	newFile, err := os.OpenFile(tmpFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open tmp host key file %+q: %v", tmpFilePath, err)
	}
	defer func() {
		_ = os.Remove(tmpFilePath)
	}()
	defer closeFileIgnoreError(newFile)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, " ")
		rewritten := false

		if len(fields) == 3 && fields[0] == hostname {
			lineKey, _, _, _, err := ssh.ParseAuthorizedKey(scanner.Bytes())
			if err == nil && lineKey != nil && lineKey.Type() == key.Type() {
				_, err := newFile.WriteString(fmt.Sprintf("%s %s", hostname, ssh.MarshalAuthorizedKey(key)))
				if err != nil {
					return err
				}
				rewritten = true
			}
		}
		if !rewritten {
			if _, err := newFile.WriteString(line + "\n"); err != nil {
				return err
			}
		}
	}

	if err := os.Rename(tmpFilePath, filePath); err != nil {
		return fmt.Errorf("failed to rename file %+q to %+q: %v", filePath, tmpFilePath, err)
	}

	return nil
}

func getHostKeyFolderPath() string {
	conf := config.GetConf()
	return filepath.Join(conf.DataFolderPath, "host_keys")
}
