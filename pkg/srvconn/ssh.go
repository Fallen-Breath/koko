package srvconn

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/jumpserver/koko/pkg/logger"
	"github.com/jumpserver/koko/pkg/utils/sshhostkey"
)

type SSHClientOption func(conf *SSHClientOptions)

type SSHClientOptions struct {
	Host         string
	Port         string
	Username     string
	Password     string
	PrivateKey   string
	Passphrase   string
	Timeout      int
	keyboardAuth gossh.KeyboardInteractiveChallenge
	PrivateAuth  gossh.Signer

	proxySSHClientOptions []SSHClientOptions
}

func (cfg *SSHClientOptions) AuthMethods() []gossh.AuthMethod {
	authMethods := make([]gossh.AuthMethod, 0, 3)

	if cfg.PrivateKey != "" {
		var (
			signer gossh.Signer
			err    error
		)
		if cfg.Passphrase != "" {
			// 先使用 passphrase 解析 PrivateKey
			if signer, err = gossh.ParsePrivateKeyWithPassphrase([]byte(cfg.PrivateKey),
				[]byte(cfg.Passphrase)); err == nil {
				authMethods = append(authMethods, gossh.PublicKeys(signer))
			}
		}
		if err != nil || cfg.Passphrase == "" {
			// 1. 如果之前使用解析失败，则去掉 passphrase，则尝试直接解析 PrivateKey 防止错误的passphrase
			// 2. 如果没有 Passphrase 则直接解析 PrivateKey
			if signer, err = gossh.ParsePrivateKey([]byte(cfg.PrivateKey)); err == nil {
				authMethods = append(authMethods, gossh.PublicKeys(signer))
			}
		}
	}
	if cfg.PrivateAuth != nil {
		authMethods = append(authMethods, gossh.PublicKeys(cfg.PrivateAuth))
	}
	if cfg.Password != "" {
		authMethods = append(authMethods, gossh.Password(cfg.Password))
	}
	if cfg.keyboardAuth != nil {
		authMethods = append(authMethods, gossh.KeyboardInteractive(cfg.keyboardAuth))
	}
	if cfg.keyboardAuth == nil && cfg.Password != "" {
		cfg.keyboardAuth = func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
			if len(questions) == 0 {
				return []string{}, nil
			}
			return []string{cfg.Password}, nil
		}
		authMethods = append(authMethods, gossh.KeyboardInteractive(cfg.keyboardAuth))
	}

	return authMethods
}

func SSHClientUsername(username string) SSHClientOption {
	return func(args *SSHClientOptions) {
		args.Username = username
	}
}

func SSHClientPassword(password string) SSHClientOption {
	return func(args *SSHClientOptions) {
		args.Password = password
	}
}

func SSHClientPrivateKey(privateKey string) SSHClientOption {
	return func(args *SSHClientOptions) {
		args.PrivateKey = privateKey
	}
}

func SSHClientPassphrase(passphrase string) SSHClientOption {
	return func(args *SSHClientOptions) {
		args.Passphrase = passphrase
	}
}

func SSHClientHost(host string) SSHClientOption {
	return func(args *SSHClientOptions) {
		args.Host = host
	}
}

func SSHClientPort(port int) SSHClientOption {
	return func(args *SSHClientOptions) {
		args.Port = strconv.Itoa(port)
	}
}

func SSHClientTimeout(timeout int) SSHClientOption {
	return func(args *SSHClientOptions) {
		args.Timeout = timeout
	}
}

func SSHClientPrivateAuth(privateAuth gossh.Signer) SSHClientOption {
	return func(args *SSHClientOptions) {
		args.PrivateAuth = privateAuth
	}
}

func SSHClientProxyClient(proxyArgs ...SSHClientOptions) SSHClientOption {
	return func(args *SSHClientOptions) {
		args.proxySSHClientOptions = proxyArgs
	}
}

func SSHClientKeyboardAuth(keyboardAuth gossh.KeyboardInteractiveChallenge) SSHClientOption {
	return func(conf *SSHClientOptions) {
		conf.keyboardAuth = keyboardAuth
	}
}

// NewSSHClient fallen's fork: check ssh host key -- add param messenger, preserve original interface
func NewSSHClient(opts ...SSHClientOption) (*SSHClient, error) {
	return NewSSHClientWithMessenger(nil, nil, opts...)
}

// NewSSHClientWithMessenger fallen's fork: check ssh host key -- add param userConn, hostKeyCallbackCallGuard
func NewSSHClientWithMessenger(userConn io.ReadWriter, hostKeyCallbackCallGuard sshhostkey.CallbackCallGuard, opts ...SSHClientOption) (*SSHClient, error) {
	cfg := &SSHClientOptions{
		Host: "127.0.0.1",
		Port: "22",
	}
	for _, setter := range opts {
		setter(cfg)
	}
	return NewSSHClientWithCfg(userConn, hostKeyCallbackCallGuard, cfg)
}

var (
	ErrNoAvailable = errors.New("no available gateway")
	ErrGatewayDial = errors.New("gateway dial addr failed")
	ErrSSHClient   = errors.New("new ssh client failed")
)

// getAvailableProxyClient: fallen's fork: check ssh host key -- add param messenger, preserve original interface
func getAvailableProxyClient(cfgs ...SSHClientOptions) (*SSHClient, error) {
	return getAvailableProxyClientWithMessenger(nil, nil, cfgs...)
}

// getAvailableProxyClientWithMessenger: fallen's fork: check ssh host key -- add param userConn, hostKeyCallbackCallGuard
func getAvailableProxyClientWithMessenger(userConn io.ReadWriter, hostKeyCallbackCallGuard sshhostkey.CallbackCallGuard, cfgs ...SSHClientOptions) (*SSHClient, error) {
	for i := range cfgs {
		if proxyClient, err := NewSSHClientWithCfg(userConn, hostKeyCallbackCallGuard, &cfgs[i]); err == nil {
			return proxyClient, nil
		}
	}
	return nil, ErrNoAvailable
}

// fallen's fork: proxyClient connection lag fix
//
// Yeet the mysterious lag in connected shell (created from proxyConn)
// when the RTT from koko to gateway is sufficiently high (e.g. >= 150ms)
//
// An easy way to observe the mysterious lag: hold down any key on the keyboard,
// and observe the smoothness of the echoed characters
//
// This issue also exists with the OpenSSH client:
// If you add "-D" to the OpenSSH client's "-L" command, its destConn will have similar lag to koko's destConn.
//
//	ssh -L 2222:127.0.0.1:22 root@example.com
//	ssh -L 2222:127.0.0.1:22 root@example.com -N    # as laggy as vanilla koko
//
// Tested with remote ssh server version: OpenSSH_8.7p1 (from RHEL 9)
// god knows why :(
func fixProxySshClientDialConnectionLag(proxyClient *SSHClient) (func(), error) {
	ses, err := proxyClient.NewSession()
	if err != nil {
		return nil, err
	}

	err = ses.Shell() // this is the magic call that yeet the connection lag
	if err != nil {
		return nil, err
	}

	return func() {
		_ = ses.Close()
	}, nil
}

func NewSSHClientWithCfg(userConn io.ReadWriter, hostKeyCallbackCallGuard sshhostkey.CallbackCallGuard, cfg *SSHClientOptions) (*SSHClient, error) {
	gosshCfg := gossh.ClientConfig{
		User:            cfg.Username,
		Auth:            cfg.AuthMethods(),
		Timeout:         time.Duration(cfg.Timeout) * time.Second,
		HostKeyCallback: sshhostkey.CreateHostKeyCallback(userConn, hostKeyCallbackCallGuard), // fallen's fork: check ssh host key -- replace HostKeyCallback
		Config:          createSSHConfig(),

		HostKeyAlgorithms: allHostKeyAlgorithms(),
	}
	destAddr := net.JoinHostPort(cfg.Host, cfg.Port)
	if len(cfg.proxySSHClientOptions) > 0 {
		proxyClient, err := getAvailableProxyClientWithMessenger(userConn, hostKeyCallbackCallGuard, cfg.proxySSHClientOptions...) // fallen's fork: check ssh host key -- add param userConn
		if err != nil {
			logger.Errorf("Get gateway client err: %s", err)
			return nil, err
		}
		logger.Infof("Get gateway client(%s) success ", proxyClient)

		// fallen's fork: proxyClient connection lag fix -- start
		if fixCloser, err := fixProxySshClientDialConnectionLag(proxyClient); err == nil {
			defer fixCloser()
			logger.Infof("Allocat dummy shell for gateway client(%s) success", proxyClient)
		} else {
			logger.Infof("Allocat dummy shell for gateway client(%s) error: %v", proxyClient, err)
		}
		// fallen's fork: proxyClient connection lag fix -- end

		destConn, err := proxyClient.Dial("tcp", destAddr)
		if err != nil {
			_ = proxyClient.Close()
			return nil, fmt.Errorf("%w: %s", ErrGatewayDial, err)
		}
		proxyConn, chans, reqs, err := gossh.NewClientConn(destConn, destAddr, &gosshCfg)
		if err != nil {
			_ = proxyClient.Close()
			_ = destConn.Close()
			return nil, fmt.Errorf("%w: %s", ErrSSHClient, err)
		}
		gosshClient := gossh.NewClient(proxyConn, chans, reqs)
		return &SSHClient{Cfg: cfg, Client: gosshClient,
			traceSessionMap: make(map[*gossh.Session]time.Time),
			ProxyClient:     proxyClient}, nil
	}
	gosshClient, err := gossh.Dial("tcp", destAddr, &gosshCfg)
	if err != nil {
		return nil, err
	}
	return &SSHClient{Client: gosshClient, Cfg: cfg,
		traceSessionMap: make(map[*gossh.Session]time.Time)}, nil
}

type SSHClient struct {
	*gossh.Client
	Cfg         *SSHClientOptions
	ProxyClient *SSHClient

	sync.Mutex

	traceSessionMap map[*gossh.Session]time.Time

	refCount int32
	_selfRef int32
}

func (s *SSHClient) increaseSelfRef() {
	s._selfRef++
}

func (s *SSHClient) decreaseSelfRef() {
	s._selfRef--
}

func (s *SSHClient) selfRef() int32 {
	return s._selfRef
}

func (s *SSHClient) String() string {
	return fmt.Sprintf("%s@%s:%s", s.Cfg.Username,
		s.Cfg.Host, s.Cfg.Port)
}

func (s *SSHClient) Close() error {
	if s.ProxyClient != nil {
		_ = s.ProxyClient.Close()
		logger.Infof("SSHClient(%s) proxy (%s) close", s, s.ProxyClient)
	}
	err := s.Client.Close()
	logger.Infof("SSHClient(%s) close", s)
	return err
}

func (s *SSHClient) RefCount() int32 {
	return atomic.LoadInt32(&s.refCount)
}

func (s *SSHClient) AcquireSession() (*gossh.Session, error) {
	atomic.AddInt32(&s.refCount, 1)
	sess, err := s.Client.NewSession()
	if err != nil {
		atomic.AddInt32(&s.refCount, -1)
		return nil, err
	}
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	s.traceSessionMap[sess] = time.Now()
	logger.Infof("SSHClient(%s) session add one ", s)
	return sess, nil
}

func (s *SSHClient) ReleaseSession(sess *gossh.Session) {
	atomic.AddInt32(&s.refCount, -1)
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	delete(s.traceSessionMap, sess)
	logger.Infof("SSHClient(%s) release one session remain %d", s, len(s.traceSessionMap))
}

func createSSHConfig() gossh.Config {
	var cfg gossh.Config
	cfg.SetDefaults()
	algos := gossh.SupportedAlgorithms()
	insecureAlgos := gossh.InsecureAlgorithms()
	ciphers := make([]string, 0, len(algos.Ciphers)+len(insecureAlgos.Ciphers))
	/*
		Change the ciphers order, placing aes128-ctr first.
		Compatible with old ssh servers.
	*/
	ciphers = append(ciphers, gossh.CipherAES128CTR)
	ciphers = append(ciphers, insecureAlgos.Ciphers...)
	ciphers = append(ciphers, algos.Ciphers...)
	keyExchanges := make([]string, 0, len(algos.KeyExchanges)+len(insecureAlgos.KeyExchanges))
	keyExchanges = append(keyExchanges, insecureAlgos.KeyExchanges...)
	keyExchanges = append(keyExchanges, algos.KeyExchanges...)
	cfg.Ciphers = ciphers
	cfg.KeyExchanges = keyExchanges
	return cfg
}

func allHostKeyAlgorithms() []string {
	supportedAlgos := gossh.SupportedAlgorithms()
	insecureAlgos := gossh.InsecureAlgorithms()
	hostKeyAlgos := make([]string, 0, len(supportedAlgos.HostKeys)+len(insecureAlgos.HostKeys)+1)
	/*
		Change the algorithm order, placing KeyAlgoED25519 first.
		Compatible with certain SSH servers.
	*/
	hostKeyAlgos = append(hostKeyAlgos, gossh.KeyAlgoED25519)
	hostKeyAlgos = append(hostKeyAlgos, supportedAlgos.HostKeys...)
	hostKeyAlgos = append(hostKeyAlgos, insecureAlgos.HostKeys...)
	return hostKeyAlgos
}
