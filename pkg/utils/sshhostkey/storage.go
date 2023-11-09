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

func getHostKey(filePath, hostname string) (ssh.PublicKey, error) {
	hostKeyStoreMutex.RLock()
	defer hostKeyStoreMutex.RUnlock()

	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer closeFileIgnoreError(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
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
			return nil, fmt.Errorf("invalid public key for host '%s': %v", host, err)
		}

		return key, nil
	}
	return nil, nil
}

func addHostKey(filePath, hostname string, key ssh.PublicKey) error {
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

func getHostKeyFolderPath() string {
	conf := config.GetConf()
	return filepath.Join(conf.DataFolderPath, "host_keys")
}
