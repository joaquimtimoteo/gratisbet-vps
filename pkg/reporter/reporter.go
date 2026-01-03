// Package reporter formata e exibe resultados do escaneamento
package reporter

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"network-scanner-edu/pkg/scanner"
)

// Reporter formata resultados para exibição
type Reporter struct {
	ShowClosed bool
	Colorize   bool
}

// NewReporter cria um reporter com configurações padrão
func NewReporter() *Reporter {
	return &Reporter{
		ShowClosed: false,
		Colorize:   true,
	}
}

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
)

// PrintResults exibe os resultados formatados
func (r *Reporter) PrintResults(results []scanner.Result, duration time.Duration) {
	// Ordena resultados por porta
	sort.Slice(results, func(i, j int) bool {
		return results[i].Target.Port < results[j].Target.Port
	})

	openCount := 0
	
	fmt.Println()
	r.printHeader("RESULTADOS DO ESCANEAMENTO")
	fmt.Println()

	for _, result := range results {
		if result.Open {
			openCount++
			r.printOpenPort(result)
		} else if r.ShowClosed {
			r.printClosedPort(result)
		}
	}

	fmt.Println()
	r.printSummary(len(results), openCount, duration)
}

func (r *Reporter) printHeader(text string) {
	line := strings.Repeat("=", 60)
	if r.Colorize {
		fmt.Printf("%s%s%s\n", colorCyan, line, colorReset)
		fmt.Printf("%s  %s%s\n", colorCyan, text, colorReset)
		fmt.Printf("%s%s%s\n", colorCyan, line, colorReset)
	} else {
		fmt.Println(line)
		fmt.Printf("  %s\n", text)
		fmt.Println(line)
	}
}

func (r *Reporter) printOpenPort(result scanner.Result) {
	service := scanner.PortService(result.Target.Port)
	
	if r.Colorize {
		fmt.Printf("%s[OPEN]%s  Port %-5d  %-12s  Latency: %v\n",
			colorGreen, colorReset,
			result.Target.Port,
			service,
			result.Latency.Round(time.Millisecond))
	} else {
		fmt.Printf("[OPEN]  Port %-5d  %-12s  Latency: %v\n",
			result.Target.Port,
			service,
			result.Latency.Round(time.Millisecond))
	}
	
	// Mostra banner se disponível
	if result.Banner != "" {
		banner := strings.TrimSpace(result.Banner)
		banner = strings.ReplaceAll(banner, "\n", " ")
		if len(banner) > 50 {
			banner = banner[:50] + "..."
		}
		fmt.Printf("        Banner: %s\n", banner)
	}
}

func (r *Reporter) printClosedPort(result scanner.Result) {
	service := scanner.PortService(result.Target.Port)
	
	if r.Colorize {
		fmt.Printf("%s[CLOSED]%s Port %-5d  %s\n",
			colorRed, colorReset,
			result.Target.Port,
			service)
	} else {
		fmt.Printf("[CLOSED] Port %-5d  %s\n",
			result.Target.Port,
			service)
	}
}

func (r *Reporter) printSummary(total, open int, duration time.Duration) {
	closed := total - open
	
	r.printHeader("RESUMO")
	fmt.Println()
	
	if r.Colorize {
		fmt.Printf("  Total de portas escaneadas: %s%d%s\n", colorBlue, total, colorReset)
		fmt.Printf("  Portas abertas:             %s%d%s\n", colorGreen, open, colorReset)
		fmt.Printf("  Portas fechadas:            %s%d%s\n", colorRed, closed, colorReset)
		fmt.Printf("  Tempo total:                %s%v%s\n", colorYellow, duration.Round(time.Millisecond), colorReset)
		fmt.Printf("  Taxa:                       %s%.2f portas/seg%s\n", 
			colorYellow, 
			float64(total)/duration.Seconds(),
			colorReset)
	} else {
		fmt.Printf("  Total de portas escaneadas: %d\n", total)
		fmt.Printf("  Portas abertas:             %d\n", open)
		fmt.Printf("  Portas fechadas:            %d\n", closed)
		fmt.Printf("  Tempo total:                %v\n", duration.Round(time.Millisecond))
		fmt.Printf("  Taxa:                       %.2f portas/seg\n", float64(total)/duration.Seconds())
	}
	fmt.Println()
}

// PrintBanner exibe o banner inicial do programa
func PrintBanner() {
	banner := `
    _   __     __  _____                                 
   / | / /__  / /_/ ___/_________ _____  ____  ___  _____
  /  |/ / _ \/ __/\__ \/ ___/ __ '/ __ \/ __ \/ _ \/ ___/
 / /|  /  __/ /_ ___/ / /__/ /_/ / / / / / / /  __/ /    
/_/ |_/\___/\__//____/\___/\__,_/_/ /_/_/ /_/\___/_/     
                                                         
    ╔═══════════════════════════════════════════════════╗
    ║  FERRAMENTA EDUCACIONAL - APENAS PARA ESTUDO     ║
    ║  Use apenas em redes que você tem permissão!     ║
    ╚═══════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}

// PrintUsageWarning exibe aviso de uso ético
func PrintUsageWarning() {
	fmt.Println(`
┌─────────────────────────────────────────────────────────────┐
│                    ⚠️  AVISO IMPORTANTE                      │
├─────────────────────────────────────────────────────────────┤
│ Esta ferramenta é APENAS para fins educacionais.            │
│                                                             │
│ ✓ USE em: sua própria rede, ambientes de lab, CTFs          │
│ ✗ NÃO USE em: redes sem autorização explícita               │
│                                                             │
│ Escaneamento não autorizado pode ser ILEGAL em seu país.    │
│ Você é responsável pelo uso desta ferramenta.               │
└─────────────────────────────────────────────────────────────┘
`)
}
