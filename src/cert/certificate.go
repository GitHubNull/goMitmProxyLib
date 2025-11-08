package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mintux/goMitmProxyLib/src/logger"
)

// CertificateManager 证书管理器接口
type CertificateManager interface {
	// 获取或创建证书
	GetCertificate(host string) (*tls.Certificate, error)

	// 生成CA证书
	GenerateCA() error

	// 加载CA证书
	LoadCA() error

	// 保存CA证书
	SaveCA() error

	// 设置证书缓存目录
	SetCacheDir(dir string)

	// 清理证书缓存
	ClearCache() error

	// 获取CA证书
	GetCACert() *x509.Certificate

	// 获取CA私钥
	GetCAPrivateKey() *rsa.PrivateKey
}

// DefaultCertificateManager 默认证书管理器实现
type DefaultCertificateManager struct {
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	cacheDir   string
	certCache  sync.Map // 证书缓存
	logger     logger.Logger
	mu         sync.RWMutex

	// CA证书文件路径
	caCertFile string
	caKeyFile  string
}

// NewDefaultCertificateManager 创建默认证书管理器
func NewDefaultCertificateManager(caCertFile, caKeyFile, cacheDir string) (*DefaultCertificateManager, error) {
	manager := &DefaultCertificateManager{
		caCertFile: caCertFile,
		caKeyFile:  caKeyFile,
		cacheDir:   cacheDir,
		logger:     logger.GetGlobalLogger(),
	}

	// 创建缓存目录
	if cacheDir != "" {
		if err := os.MkdirAll(cacheDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create cache directory: %w", err)
		}
	}

	// 加载或生成CA证书
	if err := manager.loadOrGenerateCA(); err != nil {
		return nil, fmt.Errorf("failed to load or generate CA: %w", err)
	}

	return manager, nil
}

// loadOrGenerateCA 加载或生成CA证书
func (m *DefaultCertificateManager) loadOrGenerateCA() error {
	// 尝试加载现有CA证书
	if err := m.LoadCA(); err != nil {
		m.logger.Info("CA certificate not found, generating new one")
		// 生成新的CA证书
		if err := m.GenerateCA(); err != nil {
			return fmt.Errorf("failed to generate CA certificate: %w", err)
		}
		// 保存CA证书
		if err := m.SaveCA(); err != nil {
			m.logger.Warn("Failed to save CA certificate", "error", err)
		}
	} else {
		m.logger.Info("CA certificate loaded successfully")
	}

	return nil
}

// GenerateCA 生成CA证书
func (m *DefaultCertificateManager) GenerateCA() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// 设置证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"GoMitmProxyLib CA"},
			CommonName:   "GoMitmProxyLib Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10年有效期
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// 生成证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// 解析证书
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	m.caCert = cert
	m.caKey = privateKey

	m.logger.Info("CA certificate generated successfully",
		"subject", cert.Subject,
		"not_after", cert.NotAfter,
		"serial", cert.SerialNumber)

	return nil
}

// LoadCA 加载CA证书
func (m *DefaultCertificateManager) LoadCA() error {
	if m.caCertFile == "" || m.caKeyFile == "" {
		return fmt.Errorf("CA certificate files not specified")
	}

	// 加载证书文件
	certPEM, err := os.ReadFile(m.caCertFile)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate file: %w", err)
	}

	// 解析证书
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// 加载私钥文件
	keyPEM, err := os.ReadFile(m.caKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read CA private key file: %w", err)
	}

	// 解析私钥
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		// 尝试PKCS8格式
		key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse CA private key: %w", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("CA private key is not RSA")
		}
	}

	m.mu.Lock()
	m.caCert = cert
	m.caKey = privateKey
	m.mu.Unlock()

	return nil
}

// SaveCA 保存CA证书
func (m *DefaultCertificateManager) SaveCA() error {
	if m.caCert == nil || m.caKey == nil {
		return fmt.Errorf("CA certificate not generated")
	}

	if m.caCertFile == "" || m.caKeyFile == "" {
		return fmt.Errorf("CA certificate files not specified")
	}

	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(m.caCertFile), 0755); err != nil {
		return fmt.Errorf("failed to create CA certificate directory: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(m.caKeyFile), 0755); err != nil {
		return fmt.Errorf("failed to create CA key directory: %w", err)
	}

	// 保存证书
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: m.caCert.Raw,
	})

	if err := os.WriteFile(m.caCertFile, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to save CA certificate: %w", err)
	}

	// 保存私钥
	keyBytes := x509.MarshalPKCS1PrivateKey(m.caKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})

	if err := os.WriteFile(m.caKeyFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save CA private key: %w", err)
	}

	m.logger.Info("CA certificate saved successfully",
		"cert_file", m.caCertFile,
		"key_file", m.caKeyFile)

	return nil
}

// GetCertificate 获取或创建证书
func (m *DefaultCertificateManager) GetCertificate(host string) (*tls.Certificate, error) {
	// 从缓存中查找
	if cert, ok := m.certCache.Load(host); ok {
		return cert.(*tls.Certificate), nil
	}

	// 创建新证书
	cert, err := m.generateCertificate(host)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate for %s: %w", host, err)
	}

	// 缓存证书
	m.certCache.Store(host, cert)

	// 异步保存到文件
	go m.saveCertificateToFile(host, cert)

	return cert, nil
}

// generateCertificate 生成证书
func (m *DefaultCertificateManager) generateCertificate(host string) (*tls.Certificate, error) {
	m.mu.RLock()
	if m.caCert == nil || m.caKey == nil {
		m.mu.RUnlock()
		return nil, fmt.Errorf("CA certificate not loaded")
	}
	m.mu.RUnlock()

	// 生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// 解析主机名
	hosts := []string{host}
	if ip := net.ParseIP(host); ip != nil {
		hosts = append(hosts, ip.String())
	}

	// 设置证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization: []string{"GoMitmProxyLib"},
			CommonName:   host,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1年有效期
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     hosts,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	m.mu.RLock()
	caCert := m.caCert
	caKey := m.caKey
	m.mu.RUnlock()

	// 生成证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// 创建TLS证书
	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
		Leaf:        &template,
	}

	m.logger.Debug("Generated certificate for host",
		"host", host,
		"not_after", template.NotAfter,
		"serial", template.SerialNumber)

	return cert, nil
}

// saveCertificateToFile 保存证书到文件
func (m *DefaultCertificateManager) saveCertificateToFile(host string, cert *tls.Certificate) {
	if m.cacheDir == "" {
		return
	}

	filename := filepath.Join(m.cacheDir, host+".pem")

	// 创建PEM块
	var pemData []byte

	// 添加证书
	for _, derBytes := range cert.Certificate {
		pemData = append(pemData, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derBytes,
		})...)
	}

	// 添加私钥
	if keyBytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey); err == nil {
		pemData = append(pemData, pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyBytes,
		})...)
	} else {
		// 尝试PKCS1格式
		if rsaKey, ok := cert.PrivateKey.(*rsa.PrivateKey); ok {
			keyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
			pemData = append(pemData, pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: keyBytes,
			})...)
		}
	}

	// 写入文件
	if err := os.WriteFile(filename, pemData, 0600); err != nil {
		m.logger.Warn("Failed to save certificate to file",
			"host", host,
			"file", filename,
			"error", err)
	}
}

// loadCertificateFromFile 从文件加载证书
func (m *DefaultCertificateManager) loadCertificateFromFile(host string) (*tls.Certificate, error) {
	if m.cacheDir == "" {
		return nil, fmt.Errorf("cache directory not set")
	}

	filename := filepath.Join(m.cacheDir, host+".pem")

	// 读取文件
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// 解析PEM
	var certDER [][]byte
	var privateKey interface{}

	var block *pem.Block
	rest := data
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		switch block.Type {
		case "CERTIFICATE":
			certDER = append(certDER, block.Bytes)
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
			}
			privateKey = key
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
			}
			privateKey = key
		}
	}

	if len(certDER) == 0 {
		return nil, fmt.Errorf("no certificate found in file")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("no private key found in file")
	}

	// 创建TLS证书
	cert := &tls.Certificate{
		Certificate: certDER,
		PrivateKey:  privateKey,
	}

	// 解析叶子证书
	if len(certDER) > 0 {
		leaf, err := x509.ParseCertificate(certDER[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
		}
		cert.Leaf = leaf
	}

	return cert, nil
}

// SetCacheDir 设置证书缓存目录
func (m *DefaultCertificateManager) SetCacheDir(dir string) {
	m.cacheDir = dir
	if dir != "" {
		os.MkdirAll(dir, 0755)
	}
}

// ClearCache 清理证书缓存
func (m *DefaultCertificateManager) ClearCache() error {
	m.certCache.Range(func(key, value interface{}) bool {
		m.certCache.Delete(key)
		return true
	})

	if m.cacheDir != "" {
		err := os.RemoveAll(m.cacheDir)
		if err != nil {
			return fmt.Errorf("failed to remove cache directory: %w", err)
		}
		return os.MkdirAll(m.cacheDir, 0755)
	}

	return nil
}

// GetCACert 获取CA证书
func (m *DefaultCertificateManager) GetCACert() *x509.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.caCert
}

// GetCAPrivateKey 获取CA私钥
func (m *DefaultCertificateManager) GetCAPrivateKey() *rsa.PrivateKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.caKey
}

// GetTlsConfig 获取TLS配置
func (m *DefaultCertificateManager) GetTlsConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := hello.ServerName
			if host == "" {
				// 如果没有SNI，使用连接地址
				if hello.Conn != nil {
					host, _, _ = net.SplitHostPort(hello.Conn.RemoteAddr().String())
				}
			}
			if host == "" {
				host = "localhost"
			}
			return m.GetCertificate(host)
		},
		// 启用SNI
		MinVersion: tls.VersionTLS12,
		// 接受任何客户端证书（可选）
		ClientAuth: tls.NoClientCert,
	}
}

// CertificateInfo 证书信息
type CertificateInfo struct {
	Host       string    `json:"host"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	Serial     *big.Int  `json:"serial"`
	IsExpired  bool      `json:"is_expired"`
	FilePath   string    `json:"file_path"`
}

// GetCertificateInfo 获取证书信息
func (m *DefaultCertificateManager) GetCertificateInfo(host string) (*CertificateInfo, error) {
	cert, err := m.GetCertificate(host)
	if err != nil {
		return nil, err
	}

	info := &CertificateInfo{
		Host:      host,
		NotBefore: cert.Leaf.NotBefore,
		NotAfter:  cert.Leaf.NotAfter,
		Serial:    cert.Leaf.SerialNumber,
		IsExpired: time.Now().After(cert.Leaf.NotAfter),
	}

	if m.cacheDir != "" {
		info.FilePath = filepath.Join(m.cacheDir, host+".pem")
	}

	return info, nil
}

// ListCachedCertificates 列出缓存的证书
func (m *DefaultCertificateManager) ListCachedCertificates() ([]*CertificateInfo, error) {
	var certificates []*CertificateInfo

	if m.cacheDir == "" {
		return certificates, nil
	}

	files, err := os.ReadDir(m.cacheDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache directory: %w", err)
	}

	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".pem" {
			host := strings.TrimSuffix(file.Name(), ".pem")
			info, err := m.GetCertificateInfo(host)
			if err == nil {
				certificates = append(certificates, info)
			}
		}
	}

	return certificates, nil
}

// CleanupExpiredCertificates 清理过期证书
func (m *DefaultCertificateManager) CleanupExpiredCertificates() error {
	if m.cacheDir == "" {
		return nil
	}

	certificates, err := m.ListCachedCertificates()
	if err != nil {
		return err
	}

	var cleaned int
	for _, cert := range certificates {
		if cert.IsExpired {
			if err := os.Remove(cert.FilePath); err == nil {
				m.certCache.Delete(cert.Host)
				cleaned++
			}
		}
	}

	m.logger.Info("Cleaned up expired certificates", "count", cleaned)
	return nil
}