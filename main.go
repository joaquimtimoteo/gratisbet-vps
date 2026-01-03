// Network Scanner Educacional
// Demonstra conceitos de: networking, concorrência, CLI em Go
//
// APENAS PARA FINS EDUCACIONAIS
// Use somente em redes que você tem permissão para escanear
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"network-scanner-edu/pkg/reporter"
	"network-scanner-edu/pkg/scanner"
)

// Config armazena configurações da linha de comando
type Config struct {
	Target     string
	Ports      string
	Timeout    int
	Workers    int
	ShowClosed bool
	NoColor    bool
	Help       bool
}

func main() {
	config := parseFlags()

	if config.Help {
		printHelp()
		return
	}

	// Exibe banner e aviso
	reporter.PrintBanner()
	reporter.PrintUsageWarning()

	// Valida entrada
	if config.Target == "" {
		fmt.Println("Erro: especifique um alvo com -target")
		fmt.Println("Exemplo: ./scanner -target 127.0.0.1")
		os.Exit(1)
	}

	// Configura scanner
	s := scanner.NewScanner()
	s.Timeout = time.Duration(config.Timeout) * time.Millisecond
	s.Workers = config.Workers

	// Configura reporter
	rep := reporter.NewReporter()
	rep.ShowClosed = config.ShowClosed
	rep.Colorize = !config.NoColor

	// Parse das portas
	ports := parsePorts(config.Ports)

	fmt.Printf("\n🎯 Alvo: %s\n", config.Target)
	fmt.Printf("📊 Portas: %d\n", len(ports))
	fmt.Printf("⚡ Workers: %d\n", config.Workers)
	fmt.Printf("⏱️  Timeout: %dms\n", config.Timeout)
	fmt.Println("\n🔍 Iniciando escaneamento...")

	// Gera alvos
	targets := scanner.GenerateTargets(config.Target, ports)

	// Executa escaneamento
	start := time.Now()
	results := s.ScanRange(targets)
	duration := time.Since(start)

	// Exibe resultados
	rep.PrintResults(results, duration)
}

func parseFlags() Config {
	config := Config{}

	flag.StringVar(&config.Target, "target", "", "IP ou hostname alvo (ex: 127.0.0.1)")
	flag.StringVar(&config.Target, "t", "", "IP ou hostname alvo (forma curta)")

	flag.StringVar(&config.Ports, "ports", "common", "Portas para escanear: 'common', '1-1000', ou '22,80,443'")
	flag.StringVar(&config.Ports, "p", "common", "Portas (forma curta)")

	flag.IntVar(&config.Timeout, "timeout", 2000, "Timeout em millisegundos")
	flag.IntVar(&config.Workers, "workers", 100, "Número de workers concorrentes")
	flag.BoolVar(&config.ShowClosed, "closed", false, "Mostrar portas fechadas")
	flag.BoolVar(&config.NoColor, "no-color", false, "Desabilitar cores")
	flag.BoolVar(&config.Help, "help", false, "Mostrar ajuda")
	flag.BoolVar(&config.Help, "h", false, "Mostrar ajuda (forma curta)")

	flag.Parse()

	// Target pode vir como argumento posicional
	if config.Target == "" && flag.NArg() > 0 {
		config.Target = flag.Arg(0)
	}

	return config
}

func parsePorts(portStr string) []int {
	// Portas comuns
	if portStr == "common" {
		return scanner.CommonPorts()
	}

	// Top 1000 portas
	if portStr == "full" {
		ports := make([]int, 1000)
		for i := 0; i < 1000; i++ {
			ports[i] = i + 1
		}
		return ports
	}

	var ports []int

	// Range: 1-100
	if strings.Contains(portStr, "-") {
		parts := strings.Split(portStr, "-")
		if len(parts) == 2 {
			start, _ := strconv.Atoi(parts[0])
			end, _ := strconv.Atoi(parts[1])
			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
			return ports
		}
	}

	// Lista: 22,80,443
	if strings.Contains(portStr, ",") {
		parts := strings.Split(portStr, ",")
		for _, p := range parts {
			port, err := strconv.Atoi(strings.TrimSpace(p))
			if err == nil {
				ports = append(ports, port)
			}
		}
		return ports
	}

	// Porta única
	port, err := strconv.Atoi(portStr)
	if err == nil {
		return []int{port}
	}

	// Fallback para portas comuns
	return scanner.CommonPorts()
}

func printHelp() {
	reporter.PrintBanner()

	fmt.Println(`
USO:
    ./scanner -target <IP> [opções]
    ./scanner <IP> [opções]

OPÇÕES:
    -target, -t    IP ou hostname alvo (obrigatório)
    -ports, -p     Portas para escanear:
                   - "common"   : portas mais comuns (padrão)
                   - "full"     : portas 1-1000
                   - "1-100"    : range de portas
                   - "22,80,443": lista específica
    -timeout       Timeout em ms (padrão: 2000)
    -workers       Workers concorrentes (padrão: 100)
    -closed        Mostrar portas fechadas
    -no-color      Desabilitar cores no output
    -help, -h      Mostrar esta ajuda

EXEMPLOS:
    # Escanear localhost com portas comuns
    ./scanner -t 127.0.0.1

    # Escanear portas específicas
    ./scanner -t 192.168.1.1 -p 22,80,443

    # Escanear range de portas
    ./scanner -t 10.0.0.1 -p 1-1000

    # Escaneamento rápido (menos timeout)
    ./scanner -t 127.0.0.1 -timeout 500 -workers 200

CONCEITOS DEMONSTRADOS:
    ┌─────────────────────────────────────────────────────────┐
    │ 1. Goroutines e Channels (worker pool pattern)         │
    │ 2. sync.WaitGroup para sincronização                   │
    │ 3. Mutex para acesso seguro a dados compartilhados     │
    │ 4. net.DialTimeout para conexões TCP                   │
    │ 5. flag package para parsing de CLI                    │
    │ 6. Organização de código em packages                   │
    └─────────────────────────────────────────────────────────┘
`)
}
