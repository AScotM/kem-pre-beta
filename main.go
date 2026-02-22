package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/ecdh"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "crypto/subtle"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"
)

const (
    maxMessageSize   = 100 * 1024 * 1024
    handshakeTimeout = 30 * time.Second
    readTimeout      = 5 * time.Minute
    writeTimeout     = 5 * time.Minute
    maxFilePath      = 4096
    maxConcurrent    = 100
)

type Message struct {
    Type      string          `json:"type"`
    Sender    string          `json:"sender"`
    Recipient string          `json:"recipient"`
    Timestamp int64           `json:"timestamp"`
    Payload   json.RawMessage `json:"payload"`
    Signature string          `json:"signature,omitempty"`
}

type FileMetadata struct {
    Name        string   `json:"name"`
    Size        int64    `json:"size"`
    Hash        string   `json:"hash"`
    Permissions int      `json:"permissions"`
    Tags        []string `json:"tags"`
}

type DirectoryListing struct {
    Path      string         `json:"path"`
    Files     []FileMetadata `json:"files"`
    TotalSize int64          `json:"total_size"`
    FileCount int            `json:"file_count"`
}

type SecureChannel struct {
    conn         net.Conn
    sharedSecret []byte
    sendNonce    uint64
    recvNonce    uint64
    mu           sync.Mutex
}

func NewSecureChannel(conn net.Conn, secret []byte) *SecureChannel {
    return &SecureChannel{
        conn:         conn,
        sharedSecret: secret,
        sendNonce:    0,
        recvNonce:    0,
    }
}

func (sc *SecureChannel) EncryptAndSend(data []byte) error {
    sc.mu.Lock()
    defer sc.mu.Unlock()

    if len(data) > maxMessageSize {
        return fmt.Errorf("message too large")
    }

    sc.conn.SetWriteDeadline(time.Now().Add(writeTimeout))

    nonce := make([]byte, 12)
    if sc.sendNonce == ^uint64(0) {
        return fmt.Errorf("nonce overflow")
    }
    
    if _, err := rand.Read(nonce[:4]); err != nil {
        return err
    }
    binary.BigEndian.PutUint64(nonce[4:], sc.sendNonce)
    sc.sendNonce++

    key := sha256.Sum256(sc.sharedSecret)
    block, err := aes.NewCipher(key[:16])
    if err != nil {
        return err
    }

    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }

    macKey := key[16:]
    mac := hmac.New(sha256.New, macKey)
    mac.Write(data)
    signature := mac.Sum(nil)

    payload := make([]byte, 0, len(data)+len(signature))
    payload = append(payload, data...)
    payload = append(payload, signature...)

    encrypted := aesGCM.Seal(nil, nonce, payload, nil)

    length := uint32(len(encrypted))
    if err := binary.Write(sc.conn, binary.BigEndian, length); err != nil {
        return err
    }

    if _, err := sc.conn.Write(nonce); err != nil {
        return err
    }

    _, err = sc.conn.Write(encrypted)
    return err
}

func (sc *SecureChannel) ReceiveAndDecrypt() ([]byte, error) {
    sc.mu.Lock()
    defer sc.mu.Unlock()

    sc.conn.SetReadDeadline(time.Now().Add(readTimeout))

    var length uint32
    if err := binary.Read(sc.conn, binary.BigEndian, &length); err != nil {
        return nil, err
    }

    if length > maxMessageSize {
        return nil, fmt.Errorf("message too large: %d bytes", length)
    }

    nonce := make([]byte, 12)
    if _, err := io.ReadFull(sc.conn, nonce); err != nil {
        return nil, err
    }

    encrypted := make([]byte, length)
    if _, err := io.ReadFull(sc.conn, encrypted); err != nil {
        return nil, err
    }

    expectedNonce := sc.recvNonce
    sc.recvNonce++

    actualNonce := binary.BigEndian.Uint64(nonce[4:])
    if actualNonce != expectedNonce {
        return nil, fmt.Errorf("nonce mismatch: got %d, want %d", actualNonce, expectedNonce)
    }

    key := sha256.Sum256(sc.sharedSecret)
    block, err := aes.NewCipher(key[:16])
    if err != nil {
        return nil, err
    }

    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    payload, err := aesGCM.Open(nil, nonce, encrypted, nil)
    if err != nil {
        return nil, err
    }

    if len(payload) < sha256.Size {
        return nil, fmt.Errorf("payload too short")
    }

    data := payload[:len(payload)-sha256.Size]
    receivedSignature := payload[len(payload)-sha256.Size:]

    macKey := key[16:]
    mac := hmac.New(sha256.New, macKey)
    mac.Write(data)
    expectedSignature := mac.Sum(nil)

    if subtle.ConstantTimeCompare(receivedSignature, expectedSignature) != 1 {
        return nil, fmt.Errorf("signature mismatch")
    }

    return data, nil
}

type SecureFileTransfer struct {
    channel     *SecureChannel
    workingDir  string
    sessionID   string
    rateLimiter chan struct{}
}

func NewSecureFileTransfer(channel *SecureChannel, workingDir string) *SecureFileTransfer {
    sessionID := make([]byte, 16)
    if _, err := rand.Read(sessionID); err != nil {
        sessionID = []byte("fallback-session-id")
    }

    return &SecureFileTransfer{
        channel:     channel,
        workingDir:  workingDir,
        sessionID:   hex.EncodeToString(sessionID),
        rateLimiter: make(chan struct{}, maxConcurrent),
    }
}

func (sft *SecureFileTransfer) HandleClient() error {
    defer close(sft.rateLimiter)

    for {
        data, err := sft.channel.ReceiveAndDecrypt()
        if err != nil {
            if err != io.EOF && !strings.Contains(err.Error(), "timeout") {
                log.Printf("Receive error: %v", err)
            }
            return err
        }

        var msg Message
        if err := json.Unmarshal(data, &msg); err != nil {
            log.Printf("JSON unmarshal error: %v", err)
            sft.sendError("invalid message format")
            continue
        }

        select {
        case sft.rateLimiter <- struct{}{}:
            go func(currentMsg Message) {
                defer func() {
                    if r := recover(); r != nil {
                        log.Printf("Recovered from panic: %v", r)
                    }
                    <-sft.rateLimiter
                }()
                sft.handleMessage(currentMsg)
            }(msg)
        default:
            sft.sendError("server busy")
        }
    }
}

func (sft *SecureFileTransfer) handleMessage(msg Message) {
    switch msg.Type {
    case "LIST_DIR":
        sft.handleListDirectory(msg)
    case "GET_FILE":
        sft.handleGetFile(msg)
    case "PUT_FILE":
        sft.handlePutFile(msg)
    case "DELETE_FILE":
        sft.handleDeleteFile(msg)
    case "MOVE_FILE":
        sft.handleMoveFile(msg)
    case "SEARCH":
        sft.handleSearch(msg)
    case "BATCH":
        sft.handleBatchOperation(msg)
    case "CLOSE":
        return
    default:
        sft.sendError("unknown command")
    }
}

func (sft *SecureFileTransfer) securePath(userPath string) (string, error) {
    if len(userPath) > maxFilePath {
        return "", fmt.Errorf("path too long")
    }

    cleanPath := filepath.Clean(userPath)
    fullPath := filepath.Join(sft.workingDir, cleanPath)

    if !strings.HasPrefix(fullPath, filepath.Clean(sft.workingDir)+string(os.PathSeparator)) &&
        fullPath != filepath.Clean(sft.workingDir) {
        return "", fmt.Errorf("path traversal detected")
    }

    return fullPath, nil
}

func (sft *SecureFileTransfer) handleListDirectory(msg Message) {
    var path string
    if err := json.Unmarshal(msg.Payload, &path); err != nil {
        sft.sendError("invalid path format")
        return
    }

    fullPath, err := sft.securePath(path)
    if err != nil {
        sft.sendError("invalid path")
        return
    }

    info, err := os.Stat(fullPath)
    if err != nil {
        sft.sendError("path not accessible")
        return
    }

    if !info.IsDir() {
        sft.sendError("not a directory")
        return
    }

    entries, err := os.ReadDir(fullPath)
    if err != nil {
        sft.sendError("cannot read directory")
        return
    }

    var files []FileMetadata
    var totalSize int64

    for _, entry := range entries {
        info, err := entry.Info()
        if err != nil {
            continue
        }

        h := sha256.New()
        file, err := os.Open(filepath.Join(fullPath, entry.Name()))
        if err == nil {
            func() {
                defer file.Close()
                io.Copy(h, file)
            }()
        }

        files = append(files, FileMetadata{
            Name:        entry.Name(),
            Size:        info.Size(),
            Hash:        hex.EncodeToString(h.Sum(nil)),
            Permissions: int(info.Mode().Perm()),
            Tags:        sft.generateTags(entry.Name()),
        })
        totalSize += info.Size()
    }

    listing := DirectoryListing{
        Path:      path,
        Files:     files,
        TotalSize: totalSize,
        FileCount: len(files),
    }

    sft.sendResponse("LIST_RESULT", msg.Sender, listing)
}

func (sft *SecureFileTransfer) handleGetFile(msg Message) {
    var fileInfo struct {
        Path   string `json:"path"`
        Resume bool   `json:"resume"`
        Offset int64  `json:"offset"`
    }

    if err := json.Unmarshal(msg.Payload, &fileInfo); err != nil {
        sft.sendError("invalid request format")
        return
    }

    fullPath, err := sft.securePath(fileInfo.Path)
    if err != nil {
        sft.sendError("invalid path")
        return
    }

    file, err := os.Open(fullPath)
    if err != nil {
        sft.sendError("file not accessible")
        return
    }
    defer file.Close()

    info, err := file.Stat()
    if err != nil {
        sft.sendError("cannot access file info")
        return
    }

    if info.IsDir() {
        sft.sendError("cannot get directory")
        return
    }

    if fileInfo.Resume {
        if fileInfo.Offset > info.Size() {
            sft.sendError("invalid offset")
            return
        }
        file.Seek(fileInfo.Offset, 0)
    }

    chunk := make([]byte, 65536)
    var offset int64 = fileInfo.Offset

    for {
        n, err := file.Read(chunk)
        if n > 0 {
            sft.sendFileChunk(fileInfo.Path, offset, chunk[:n], false, msg.Sender)
            offset += int64(n)
        }

        if err == io.EOF {
            sft.sendFileChunk(fileInfo.Path, offset, []byte{}, true, msg.Sender)
            break
        }

        if err != nil {
            sft.sendError("read error")
            return
        }
    }
}

func (sft *SecureFileTransfer) handlePutFile(msg Message) {
    var fileInfo struct {
        Path   string `json:"path"`
        Size   int64  `json:"size"`
        Hash   string `json:"hash"`
        Chunks int    `json:"chunks"`
    }

    if err := json.Unmarshal(msg.Payload, &fileInfo); err != nil {
        sft.sendError("invalid request format")
        return
    }

    if fileInfo.Size > maxMessageSize*10 {
        sft.sendError("file too large")
        return
    }

    fullPath, err := sft.securePath(fileInfo.Path)
    if err != nil {
        sft.sendError("invalid path")
        return
    }

    os.MkdirAll(filepath.Dir(fullPath), 0755)

    file, err := os.Create(fullPath)
    if err != nil {
        sft.sendError("cannot create file")
        return
    }
    defer file.Close()

    sft.sendResponse("PUT_ACK", msg.Sender, map[string]bool{"ready": true})

    h := sha256.New()
    writer := io.MultiWriter(file, h)

    for i := 0; i < fileInfo.Chunks; i++ {
        data, err := sft.channel.ReceiveAndDecrypt()
        if err != nil {
            sft.sendError("transfer failed")
            os.Remove(fullPath)
            return
        }

        var chunkMsg Message
        if err := json.Unmarshal(data, &chunkMsg); err != nil {
            sft.sendError("invalid chunk format")
            os.Remove(fullPath)
            return
        }

        var chunk struct {
            Data  []byte `json:"data"`
            Index int    `json:"index"`
        }
        if err := json.Unmarshal(chunkMsg.Payload, &chunk); err != nil {
            sft.sendError("invalid chunk data")
            os.Remove(fullPath)
            return
        }

        if _, err := writer.Write(chunk.Data); err != nil {
            sft.sendError("write error")
            os.Remove(fullPath)
            return
        }

        sft.sendResponse("PUT_PROGRESS", msg.Sender, map[string]int{
            "received": i + 1,
            "total":    fileInfo.Chunks,
        })
    }

    computedHash := hex.EncodeToString(h.Sum(nil))
    if subtle.ConstantTimeCompare([]byte(computedHash), []byte(fileInfo.Hash)) != 1 {
        os.Remove(fullPath)
        sft.sendError("hash mismatch")
        return
    }

    sft.sendResponse("PUT_COMPLETE", msg.Sender, map[string]string{"hash": computedHash})
}

func (sft *SecureFileTransfer) handleDeleteFile(msg Message) {
    var path string
    if err := json.Unmarshal(msg.Payload, &path); err != nil {
        sft.sendError("invalid path format")
        return
    }

    fullPath, err := sft.securePath(path)
    if err != nil {
        sft.sendError("invalid path")
        return
    }

    info, err := os.Stat(fullPath)
    if err != nil {
        sft.sendError("path not accessible")
        return
    }

    if info.IsDir() {
        if err := os.RemoveAll(fullPath); err != nil {
            sft.sendError("cannot remove directory")
            return
        }
    } else {
        if err := os.Remove(fullPath); err != nil {
            sft.sendError("cannot remove file")
            return
        }
    }

    sft.sendResponse("DELETE_COMPLETE", msg.Sender, map[string]string{"deleted": path})
}

func (sft *SecureFileTransfer) handleMoveFile(msg Message) {
    var paths struct {
        Source string `json:"source"`
        Dest   string `json:"dest"`
    }

    if err := json.Unmarshal(msg.Payload, &paths); err != nil {
        sft.sendError("invalid request format")
        return
    }

    sourcePath, err := sft.securePath(paths.Source)
    if err != nil {
        sft.sendError("invalid source path")
        return
    }

    destPath, err := sft.securePath(paths.Dest)
    if err != nil {
        sft.sendError("invalid destination path")
        return
    }

    if _, err := os.Stat(sourcePath); err != nil {
        sft.sendError("source not accessible")
        return
    }

    os.MkdirAll(filepath.Dir(destPath), 0755)

    if err := os.Rename(sourcePath, destPath); err != nil {
        sft.sendError("move failed")
        return
    }

    sft.sendResponse("MOVE_COMPLETE", msg.Sender, map[string]bool{"moved": true})
}

func (sft *SecureFileTransfer) handleSearch(msg Message) {
    var searchQuery struct {
        Pattern string   `json:"pattern"`
        Tags    []string `json:"tags"`
        MinSize int64    `json:"min_size"`
        MaxSize int64    `json:"max_size"`
    }

    if err := json.Unmarshal(msg.Payload, &searchQuery); err != nil {
        sft.sendError("invalid search query")
        return
    }

    var results []FileMetadata
    var resultsMu sync.Mutex
    var wg sync.WaitGroup
    semaphore := make(chan struct{}, 10)

    err := filepath.Walk(sft.workingDir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            log.Printf("Walk error at %s: %v", path, err)
            return nil
        }
        
        if info.IsDir() {
            return nil
        }

        wg.Add(1)
        go func(currentPath string, fileInfo os.FileInfo) {
            defer wg.Done()
            semaphore <- struct{}{}
            defer func() { <-semaphore }()

            relPath, _ := filepath.Rel(sft.workingDir, currentPath)

            if searchQuery.Pattern != "" {
                matched, _ := filepath.Match(searchQuery.Pattern, fileInfo.Name())
                if !matched && !strings.Contains(relPath, searchQuery.Pattern) {
                    return
                }
            }

            if searchQuery.MinSize > 0 && fileInfo.Size() < searchQuery.MinSize {
                return
            }

            if searchQuery.MaxSize > 0 && fileInfo.Size() > searchQuery.MaxSize {
                return
            }

            tags := sft.generateTags(fileInfo.Name())
            if len(searchQuery.Tags) > 0 {
                tagMatch := false
                for _, requiredTag := range searchQuery.Tags {
                    for _, fileTag := range tags {
                        if requiredTag == fileTag {
                            tagMatch = true
                            break
                        }
                    }
                    if tagMatch {
                        break
                    }
                }
                if !tagMatch {
                    return
                }
            }

            h := sha256.New()
            file, openErr := os.Open(currentPath)
            if openErr == nil {
                func() {
                    defer file.Close()
                    io.Copy(h, file)
                }()
            }

            resultsMu.Lock()
            results = append(results, FileMetadata{
                Name:        relPath,
                Size:        fileInfo.Size(),
                Hash:        hex.EncodeToString(h.Sum(nil)),
                Permissions: int(fileInfo.Mode().Perm()),
                Tags:        tags,
            })
            resultsMu.Unlock()
        }(path, info)

        return nil
    })

    if err != nil {
        log.Printf("Walk error: %v", err)
    }

    wg.Wait()
    sft.sendResponse("SEARCH_RESULT", msg.Sender, results)
}

func (sft *SecureFileTransfer) handleBatchOperation(msg Message) {
    var operations []struct {
        Type   string          `json:"type"`
        Params json.RawMessage `json:"params"`
    }

    if err := json.Unmarshal(msg.Payload, &operations); err != nil {
        sft.sendError("invalid batch format")
        return
    }

    results := make([]map[string]interface{}, 0, len(operations))

    for _, op := range operations {
        result := map[string]interface{}{
            "operation": op.Type,
        }

        switch op.Type {
        case "GET_FILE_INFO":
            var path string
            if err := json.Unmarshal(op.Params, &path); err != nil {
                result["error"] = "invalid path"
            } else {
                fullPath, err := sft.securePath(path)
                if err != nil {
                    result["error"] = "invalid path"
                } else {
                    info, err := os.Stat(fullPath)
                    if err != nil {
                        result["error"] = "not accessible"
                        result["exists"] = false
                    } else {
                        result["exists"] = true
                        result["is_dir"] = info.IsDir()
                        result["size"] = info.Size()
                        result["mode"] = info.Mode().String()
                    }
                }
            }

        case "DELETE_FILE":
            var path string
            if err := json.Unmarshal(op.Params, &path); err != nil {
                result["error"] = "invalid path"
                result["success"] = false
            } else {
                fullPath, err := sft.securePath(path)
                if err != nil {
                    result["error"] = "invalid path"
                    result["success"] = false
                } else {
                    err := os.Remove(fullPath)
                    result["success"] = err == nil
                    if err != nil {
                        result["error"] = err.Error()
                    }
                }
            }

        case "CREATE_DIR":
            var path string
            if err := json.Unmarshal(op.Params, &path); err != nil {
                result["error"] = "invalid path"
                result["success"] = false
            } else {
                fullPath, err := sft.securePath(path)
                if err != nil {
                    result["error"] = "invalid path"
                    result["success"] = false
                } else {
                    err := os.MkdirAll(fullPath, 0755)
                    result["success"] = err == nil
                    if err != nil {
                        result["error"] = err.Error()
                    }
                }
            }

        default:
            result["error"] = "unknown operation"
        }

        results = append(results, result)
    }

    sft.sendResponse("BATCH_RESULT", msg.Sender, results)
}

func (sft *SecureFileTransfer) sendResponse(msgType, recipient string, payload interface{}) {
    payloadData, err := json.Marshal(payload)
    if err != nil {
        log.Printf("Failed to marshal response: %v", err)
        return
    }

    response := Message{
        Type:      msgType,
        Sender:    "server",
        Recipient: recipient,
        Timestamp: time.Now().Unix(),
        Payload:   payloadData,
    }

    responseData, err := json.Marshal(response)
    if err != nil {
        log.Printf("Failed to marshal message: %v", err)
        return
    }

    if err := sft.channel.EncryptAndSend(responseData); err != nil {
        log.Printf("Failed to send response: %v", err)
    }
}

func (sft *SecureFileTransfer) sendFileChunk(path string, offset int64, data []byte, eof bool, recipient string) {
    chunkData := struct {
        Path   string `json:"path"`
        Offset int64  `json:"offset"`
        Data   []byte `json:"data"`
        Eof    bool   `json:"eof"`
    }{
        Path:   path,
        Offset: offset,
        Data:   data,
        Eof:    eof,
    }

    sft.sendResponse("FILE_CHUNK", recipient, chunkData)
}

func (sft *SecureFileTransfer) sendError(errMsg string) {
    errorPayload, _ := json.Marshal(map[string]string{"error": errMsg})
    
    errorMsg := Message{
        Type:      "ERROR",
        Sender:    "server",
        Timestamp: time.Now().Unix(),
        Payload:   json.RawMessage(errorPayload),
    }

    data, err := json.Marshal(errorMsg)
    if err != nil {
        log.Printf("Failed to marshal error: %v", err)
        return
    }

    if err := sft.channel.EncryptAndSend(data); err != nil {
        log.Printf("Failed to send error: %v", err)
    }
}

func (sft *SecureFileTransfer) generateTags(filename string) []string {
    tags := make([]string, 0)

    ext := strings.ToLower(filepath.Ext(filename))
    switch ext {
    case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp":
        tags = append(tags, "image")
    case ".pdf", ".doc", ".docx", ".txt", ".rtf", ".odt":
        tags = append(tags, "document")
    case ".mp3", ".wav", ".flac", ".m4a", ".ogg":
        tags = append(tags, "audio")
    case ".mp4", ".avi", ".mkv", ".mov", ".wmv":
        tags = append(tags, "video")
    case ".zip", ".tar", ".gz", ".7z", ".rar":
        tags = append(tags, "archive")
    case ".go", ".py", ".js", ".c", ".cpp", ".java":
        tags = append(tags, "source")
    case ".exe", ".bin", ".msi":
        tags = append(tags, "executable")
    }

    lowerName := strings.ToLower(filename)
    if strings.Contains(lowerName, "backup") {
        tags = append(tags, "backup")
    }
    if strings.Contains(lowerName, "temp") || strings.Contains(lowerName, "tmp") {
        tags = append(tags, "temporary")
    }
    if strings.Contains(lowerName, "confidential") || strings.Contains(lowerName, "secret") {
        tags = append(tags, "confidential")
    }
    if strings.Contains(lowerName, "config") || strings.Contains(lowerName, "settings") {
        tags = append(tags, "config")
    }

    return tags
}

func main() {
    os.MkdirAll("./server_files", 0755)
    os.MkdirAll("./client_files", 0755)

    var wg sync.WaitGroup
    wg.Add(2)

    go aliceServer(&wg)
    go bobClient(&wg)

    wg.Wait()
}

func aliceServer(wg *sync.WaitGroup) {
    defer wg.Done()

    listener, err := net.Listen("tcp", "localhost:8080")
    if err != nil {
        log.Fatal(err)
    }
    defer listener.Close()

    log.Println("Server listening on localhost:8080")

    conn, err := listener.Accept()
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    conn.SetDeadline(time.Now().Add(handshakeTimeout))

    curve := ecdh.P256()
    privateKey, err := curve.GenerateKey(rand.Reader)
    if err != nil {
        log.Fatal(err)
    }

    publicKeyBytes := privateKey.PublicKey().Bytes()
    keyLen := uint16(len(publicKeyBytes))
    lenBuf := make([]byte, 2)
    binary.BigEndian.PutUint16(lenBuf, keyLen)

    if _, err := conn.Write(lenBuf); err != nil {
        log.Fatal(err)
    }

    if _, err := conn.Write(publicKeyBytes); err != nil {
        log.Fatal(err)
    }

    peerKeyLenBuf := make([]byte, 2)
    if _, err := io.ReadFull(conn, peerKeyLenBuf); err != nil {
        log.Fatal(err)
    }
    peerKeyLen := binary.BigEndian.Uint16(peerKeyLenBuf)

    peerPublicKeyBytes := make([]byte, peerKeyLen)
    if _, err := io.ReadFull(conn, peerPublicKeyBytes); err != nil {
        log.Fatal(err)
    }

    peerPublicKey, err := curve.NewPublicKey(peerPublicKeyBytes)
    if err != nil {
        log.Fatal(err)
    }

    sharedSecret, err := privateKey.ECDH(peerPublicKey)
    if err != nil {
        log.Fatal(err)
    }

    conn.SetDeadline(time.Time{})

    channel := NewSecureChannel(conn, sharedSecret)
    transfer := NewSecureFileTransfer(channel, "./server_files")

    fmt.Println("Alice: Secure file server ready")
    transfer.HandleClient()
}

func bobClient(wg *sync.WaitGroup) {
    defer wg.Done()

    var conn net.Conn
    var err error

    for i := 0; i < 10; i++ {
        conn, err = net.Dial("tcp", "localhost:8080")
        if err == nil {
            break
        }
        time.Sleep(100 * time.Millisecond)
    }

    if err != nil {
        log.Fatal("Failed to connect to server:", err)
    }
    defer conn.Close()

    conn.SetDeadline(time.Now().Add(handshakeTimeout))

    curve := ecdh.P256()
    privateKey, err := curve.GenerateKey(rand.Reader)
    if err != nil {
        log.Fatal(err)
    }

    peerKeyLenBuf := make([]byte, 2)
    if _, err := io.ReadFull(conn, peerKeyLenBuf); err != nil {
        log.Fatal(err)
    }
    peerKeyLen := binary.BigEndian.Uint16(peerKeyLenBuf)

    peerPublicKeyBytes := make([]byte, peerKeyLen)
    if _, err := io.ReadFull(conn, peerPublicKeyBytes); err != nil {
        log.Fatal(err)
    }

    peerPublicKey, err := curve.NewPublicKey(peerPublicKeyBytes)
    if err != nil {
        log.Fatal(err)
    }

    publicKeyBytes := privateKey.PublicKey().Bytes()
    keyLen := uint16(len(publicKeyBytes))
    keyLenBuf := make([]byte, 2)
    binary.BigEndian.PutUint16(keyLenBuf, keyLen)

    if _, err := conn.Write(keyLenBuf); err != nil {
        log.Fatal(err)
    }

    if _, err := conn.Write(publicKeyBytes); err != nil {
        log.Fatal(err)
    }

    sharedSecret, err := privateKey.ECDH(peerPublicKey)
    if err != nil {
        log.Fatal(err)
    }

    conn.SetDeadline(time.Time{})

    channel := NewSecureChannel(conn, sharedSecret)

    fmt.Println("Bob: Connected to secure file server")

    testFile := []byte("This is a confidential document\nProject X - Launch codes: 4792-8841-AA38\nBackup codes: 7721-3365-ZZ91")
    if err := os.WriteFile("./client_files/secret.txt", testFile, 0644); err != nil {
        log.Printf("Warning: Could not create test file: %v", err)
    }

    listDirMsg := Message{
        Type:      "LIST_DIR",
        Sender:    "bob",
        Recipient: "server",
        Timestamp: time.Now().Unix(),
        Payload:   json.RawMessage(`"."`),
    }
    listData, _ := json.Marshal(listDirMsg)
    channel.EncryptAndSend(listData)

    response, _ := channel.ReceiveAndDecrypt()
    fmt.Printf("Directory listing: %s\n", string(response))

    searchMsg := Message{
        Type:      "SEARCH",
        Sender:    "bob",
        Recipient: "server",
        Timestamp: time.Now().Unix(),
        Payload:   json.RawMessage(`{"pattern":"*.txt","tags":["document"]}`),
    }
    searchData, _ := json.Marshal(searchMsg)
    channel.EncryptAndSend(searchData)

    response, _ = channel.ReceiveAndDecrypt()
    fmt.Printf("Search results: %s\n", string(response))

    closeMsg := Message{
        Type:      "CLOSE",
        Sender:    "bob",
        Recipient: "server",
        Timestamp: time.Now().Unix(),
        Payload:   json.RawMessage(`{}`),
    }
    closeData, _ := json.Marshal(closeMsg)
    channel.EncryptAndSend(closeData)

    fmt.Println("Bob: Session complete")
}
