package main

import (
    "bufio"
    "crypto/aes"
    "crypto/cipher"
    "crypto/ecdh"
    "crypto/rand"
    "io"
    "fmt"
    "log"
    "net"
    "os"
    "os/signal"
    "sync"
    
    "github.com/awnumar/memguard"
)

var (
    clientConnected = false
    clientMutex     sync.Mutex
)

func main() {
    // Initialize memguard
    memguard.CatchInterrupt()
    defer memguard.Purge()

    listener, err := net.Listen("tcp", "127.0.0.1:8083")
    if err != nil {
        log.Fatalf("Error starting the server: %v", err)
    }
    defer listener.Close()
    fmt.Println("Server is running and waiting for connections...")

    for {
        conn, err := listener.Accept()
        if err != nil {
            fmt.Println("Error accepting connection: %v", err)
            continue
        }

        clientMutex.Lock()
        if clientConnected {
            clientMutex.Unlock()
            fmt.Println("Connection attempt rejected: Line Busy.")
            handleBusyConnection(conn)
            continue
        }
        clientConnected = true
        clientMutex.Unlock()

        fmt.Println("Client connected.")
        go handleConnection(conn)
    }
}

func handleBusyConnection(conn net.Conn) {
    conn.Write([]byte("Line Busy\n"))
    conn.Close()
}

func handleConnection(conn net.Conn) {
    defer func() {
        conn.Close()
        clientMutex.Lock()
        clientConnected = false
        clientMutex.Unlock()
        fmt.Println("Client disconnected.")
    }()

    curve := ecdh.X25519()
    privateKey, err := curve.GenerateKey(rand.Reader)
    if err != nil {
        log.Printf("Error generating private key: %v", err)
        return
    }

    privateKeyBuffer := memguard.NewBufferFromBytes(privateKey.Bytes())
    defer privateKeyBuffer.Destroy()

    publicKey := privateKey.PublicKey()

    clientPublicKeyBytes := make([]byte, 32) // X25519 uses 32-byte keys
    _, err = io.ReadFull(conn, clientPublicKeyBytes)
    if err != nil {
        log.Printf("Error receiving the client's public key: %v", err)
        return
    }

    clientPublicKey, err := curve.NewPublicKey(clientPublicKeyBytes)
    if err != nil {
        log.Printf("Error parsing the client's public key: %v", err)
        return
    }

    publicKeyBytes := publicKey.Bytes()
    conn.Write(publicKeyBytes)

    sharedSecret, err := privateKey.ECDH(clientPublicKey)
    if err != nil {
        log.Printf("Error calculating the shared secret: %v", err)
        return
    }

    sharedSecretBuffer := memguard.NewBufferFromBytes(sharedSecret)
    defer sharedSecretBuffer.Destroy()

    block, err := aes.NewCipher(sharedSecret)
    if err != nil {
        log.Printf("Error initializing AES cipher: %v", err)
        return
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        log.Printf("Error initializing GCM mode: %v", err)
        return
    }

    var wg sync.WaitGroup
    wg.Add(2)

    go receiveMessages(conn, gcm, &wg)
    go sendMessages(conn, gcm, &wg)

    wg.Wait()
}

func receiveMessages(conn net.Conn, gcm cipher.AEAD, wg *sync.WaitGroup) {
    defer wg.Done()
    buf := make([]byte, 4096)
    for {
        n, err := conn.Read(buf)
        if err != nil {
            fmt.Println("Error reading message: %v", err)
            return
        }

        decrypted, err := gcm.Open(nil, buf[:12], buf[12:n], nil)
        if err != nil {
            fmt.Println("Error decrypting message: %v", err)
            return
        }

        if string(decrypted) == ".QUIT" {
            clientMutex.Lock()
            clientConnected = false
            clientMutex.Unlock()
            os.Exit(0)
        }

	fmt.Println(string(decrypted))
    }
}

func sendMessages(conn net.Conn, gcm cipher.AEAD, wg *sync.WaitGroup) {
    defer wg.Done()
    scanner := bufio.NewScanner(os.Stdin)

    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt)
    go func() {
        <-c
        nonce := make([]byte, 12)
        io.ReadFull(rand.Reader, nonce)
        encrypted := gcm.Seal(nil, nonce, []byte(".QUIT"), nil)
        conn.Write(append(nonce, encrypted...))
        clientMutex.Lock()
        clientConnected = false
        clientMutex.Unlock()
        os.Exit(0)
    }()

    for scanner.Scan() {
        message := scanner.Text()
        if message == ".QUIT" {
            nonce := make([]byte, 12)
            io.ReadFull(rand.Reader, nonce)
            encrypted := gcm.Seal(nil, nonce, []byte(message), nil)
            conn.Write(append(nonce, encrypted...))
            clientMutex.Lock()
            clientConnected = false
            clientMutex.Unlock()
            os.Exit(0)
        }
        nonce := make([]byte, 12)
        if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
            fmt.Println("Error generating nonce: %v", err)
            return
        }
        encrypted := gcm.Seal(nil, nonce, []byte(message), nil)
        conn.Write(append(nonce, encrypted...))
    }
}
