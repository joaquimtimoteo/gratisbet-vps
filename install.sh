#!/bin/bash

# ============================================
# GratisBet VPS - Script de Instalação
# ============================================

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║           🎰 GRATISBET VPS - INSTALAÇÃO                   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Verificar se é root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}❌ Execute como root: sudo ./install.sh${NC}"
  exit 1
fi

echo -e "${YELLOW}📦 Atualizando sistema...${NC}"
apt update -y

echo -e "${YELLOW}📦 Instalando dependências...${NC}"
apt install -y curl wget git ufw

# Instalar Go se não existir
if ! command -v /usr/local/go/bin/go &> /dev/null; then
    echo -e "${YELLOW}📦 Instalando Go 1.21.5...${NC}"
    cd /tmp
    wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    export PATH=$PATH:/usr/local/go/bin
fi

echo -e "${GREEN}✅ Go instalado: $(/usr/local/go/bin/go version)${NC}"

# Compilar servidor
echo -e "${YELLOW}🔨 Compilando servidor...${NC}"
cd /opt/gratisbet/vps-server
/usr/local/go/bin/go build -o server main.go

if [ ! -f server ]; then
    echo -e "${RED}❌ Erro na compilação${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Servidor compilado${NC}"

# Configurar firewall
echo -e "${YELLOW}🔥 Configurando firewall...${NC}"
ufw allow 22/tcp
ufw allow 443/tcp
ufw allow 8080/tcp
ufw --force enable

# Criar serviço systemd
echo -e "${YELLOW}⚙️ Criando serviço systemd...${NC}"
cat > /etc/systemd/system/gratisbet.service << 'SVCEOF'
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
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable gratisbet
systemctl start gratisbet

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           ✅ INSTALAÇÃO CONCLUÍDA!                        ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "📊 Status do serviço:"
systemctl status gratisbet --no-pager -l
echo ""
echo -e "${YELLOW}📱 Endpoints:${NC}"
echo -e "   • HTTP:   http://216.106.176.133:8080/tunnel"
echo -e "   • TLS:    https://216.106.176.133:443/tunnel"
echo -e "   • Health: http://216.106.176.133:8080/health"
echo ""
echo -e "${YELLOW}🔧 Comandos úteis:${NC}"
echo -e "   • Ver logs:    journalctl -u gratisbet -f"
echo -e "   • Reiniciar:   systemctl restart gratisbet"
echo -e "   • Parar:       systemctl stop gratisbet"
echo -e "   • Status:      systemctl status gratisbet"
echo ""
