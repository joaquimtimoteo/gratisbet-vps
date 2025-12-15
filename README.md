# GratisBet VPS Server

Servidor VPN/Proxy para a VPS com suporte a HTTP e TLS/SNI.

## Características

- ✅ HTTP na porta 8080
- ✅ TLS/HTTPS na porta 443 com SNI customizado
- ✅ Autenticação por usuário/senha
- ✅ Tunnel TCP transparente
- ✅ Estatísticas em tempo real
- ✅ Certificado TLS auto-gerado

## Instalação na VPS

### 1. Conectar à VPS

```bash
ssh root@216.106.176.133
```

### 2. Instalar Go (se necessário)

```bash
cd /tmp
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

### 3. Clonar e compilar

```bash
cd /opt
git clone https://github.com/pfrancisco43/igris-vpn.git gratisbet
cd gratisbet/vps-server
/usr/local/go/bin/go build -o server main.go
```

### 4. Abrir portas no firewall

```bash
ufw allow 22/tcp
ufw allow 443/tcp
ufw allow 8080/tcp
ufw --force enable
```

### 5. Executar

```bash
./server
```

### 6. Criar serviço systemd (para rodar automaticamente)

```bash
cat > /etc/systemd/system/gratisbet.service << 'EOF'
[Unit]
Description=GratisBet VPS Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/gratisbet/vps-server
ExecStart=/opt/gratisbet/vps-server/server
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable gratisbet
systemctl start gratisbet
systemctl status gratisbet
```

## Endpoints

| Endpoint | Porta | Descrição |
|----------|-------|-----------|
| `/tunnel` | 8080 (HTTP) | Tunnel proxy (sem TLS) |
| `/tunnel` | 443 (TLS) | Tunnel proxy com SNI spoofing |
| `/health` | 8080 | Health check |
| `/status` | 8080 | Status JSON |

## Configuração iOS

No `TunnelManager.swift`, configure:

```swift
// Para HTTP (sem SNI)
private let serverHost = "216.106.176.133"
private let serverPort: UInt16 = 8080
private let useSNI = false

// Para TLS com SNI (dados grátis)
private let serverHost = "216.106.176.133"
private let serverPort: UInt16 = 443
private let useSNI = true
private let sniHost = "signup.ao"
```

## Autenticação

- **Usuário**: `user_admin`
- **Senha**: `Q7!mA9#KpR2$VxL@eT6Z`

## Testar

```bash
# Health check HTTP
curl http://216.106.176.133:8080/health

# Health check TLS (ignora certificado auto-assinado)
curl -k https://216.106.176.133:443/health

# Status JSON
curl http://216.106.176.133:8080/status
```

## Logs

O servidor mostra logs em tempo real:
- 📥 Conexões recebidas
- ✅ Autenticação bem-sucedida
- 🚫 Autenticação falhou
- 🔌 Conexões fechadas
- 📊 Estatísticas a cada 60 segundos
