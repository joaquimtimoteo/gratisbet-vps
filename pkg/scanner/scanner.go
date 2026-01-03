// Package scanner demonstra conceitos de escaneamento de rede
// APENAS PARA FINS EDUCACIONAIS - Use apenas em redes que você tem permissão
package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// Target representa um alvo de escaneamento
type Target struct {
	IP   string
	Port int
}

// Result representa o resultado de uma tentativa de conexão
type Result struct {
	Target  Target
	Open    bool
	Banner  string
	Latency time.Duration
	Error   error
}

// Scanner é a estrutura principal do escaneador
type Scanner struct {
	Timeout    time.Duration
	Workers    int
	GrabBanner bool
}

// NewScanner cria um novo scanner com configurações padrão
func NewScanner() *Scanner {
	return &Scanner{
		Timeout:    2 * time.Second,
		Workers:    100, // Worker pool para demonstrar concorrência
		GrabBanner: true,
	}
}

// ScanPort verifica se uma porta está aberta em um IP
// Demonstra: conexão TCP básica e timeout handling
func (s *Scanner) ScanPort(target Target) Result {
	result := Result{Target: target}
	
	address := fmt.Sprintf("%s:%d", target.IP, target.Port)
	start := time.Now()
	
	// Tenta estabelecer conexão TCP
	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	result.Latency = time.Since(start)
	
	if err != nil {
		result.Open = false
		result.Error = err
		return result
	}
	defer conn.Close()
	
	result.Open = true
	
	// Tenta capturar banner (identificação do serviço)
	if s.GrabBanner {
		result.Banner = s.grabBanner(conn)
	}
	
	return result
}

// grabBanner tenta ler dados iniciais da conexão
func (s *Scanner) grabBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}
	
	return string(buffer[:n])
}

// ScanRange escaneia múltiplos alvos usando worker pool
// Demonstra: goroutines, channels, sync.WaitGroup
func (s *Scanner) ScanRange(targets []Target) []Result {
	var results []Result
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// Channel para distribuir trabalho (job queue)
	jobs := make(chan Target, len(targets))
	
	// Inicia worker pool
	// Conceito: limitamos goroutines para não sobrecarregar
	for i := 0; i < s.Workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			// Cada worker processa jobs do channel
			for target := range jobs {
				result := s.ScanPort(target)
				
				// Mutex protege acesso concorrente ao slice
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}(i)
	}
	
	// Envia todos os alvos para o channel
	for _, target := range targets {
		jobs <- target
	}
	close(jobs) // Sinaliza que não há mais jobs
	
	// Aguarda todos os workers terminarem
	wg.Wait()
	
	return results
}

// GenerateTargets cria lista de alvos para um range de IPs
// Demonstra: geração de ranges para escaneamento
func GenerateTargets(baseIP string, ports []int) []Target {
	var targets []Target
	
	for _, port := range ports {
		targets = append(targets, Target{
			IP:   baseIP,
			Port: port,
		})
	}
	
	return targets
}

// CommonPorts retorna portas comumente escaneadas
func CommonPorts() []int {
	return []int{
		21,   // FTP
		22,   // SSH
		23,   // Telnet
		25,   // SMTP
		53,   // DNS
		80,   // HTTP
		110,  // POP3
		143,  // IMAP
		443,  // HTTPS
		445,  // SMB
		3306, // MySQL
		3389, // RDP
		5432, // PostgreSQL
		6379, // Redis
		8080, // HTTP Alt
		8443, // HTTPS Alt
	}
}

// PortService retorna o nome do serviço associado à porta
func PortService(port int) string {
	services := map[int]string{
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		143:  "IMAP",
		443:  "HTTPS",
		445:  "SMB",
		3306: "MySQL",
		3389: "RDP",
		5432: "PostgreSQL",
		6379: "Redis",
		8080: "HTTP-Alt",
		8443: "HTTPS-Alt",
	}
	
	if name, ok := services[port]; ok {
		return name
	}
	return "Unknown"
}
