package main

import (
    "bufio"
    "crypto/aes"
    "crypto/cipher"
    "crypto/ecdh"
    "crypto/rand"
    "flag"
    "fmt"
    "io"
    "net"
    "net/url"
    "os"
    "os/signal"
    "sync"
    
    "github.com/awnumar/memguard"
    "golang.org/x/net/proxy"
)

func main() {
    // Initialize memguard
    memguard.CatchInterrupt()
    defer memguard.Purge()

    serverURL := flag.String("u", "", "Server URL in the format <Server-Onion-URL>:<Port>")
    flag.Parse()

    if *serverURL == "" {
        fmt.Println("Please enter the Onion URL and the port with the -u parameter.")
        os.Exit(1)
    }

    torProxyUrl, _ := url.Parse("socks5://127.0.0.1:9050")
    dialer, _ := proxy.FromURL(torProxyUrl, proxy.Direct)

    conn, err := dialer.Dial("tcp", *serverURL)
    if err != nil {
        fmt.Println("Error connecting to the server:", err)
        return
    }
    defer conn.Close()

    fmt.Println("Connected to the server.")

    curve := ecdh.X25519()
    privateKey, err := curve.GenerateKey(rand.Reader)
    if err != nil {
        fmt.Println("Error generating private key:", err)
        return
    }

    privateKeyBuffer := memguard.NewBufferFromBytes(privateKey.Bytes())
    defer privateKeyBuffer.Destroy()

    publicKey := privateKey.PublicKey()
    publicKeyBytes := publicKey.Bytes()
    conn.Write(publicKeyBytes)

    serverPublicKeyBytes := make([]byte, 32) // X25519 uses 32-byte keys
    _, err = io.ReadFull(conn, serverPublicKeyBytes)
    if err != nil {
        fmt.Println("Error receiving the server's public key - line busy")
        return
    }

    serverPublicKey, err := curve.NewPublicKey(serverPublicKeyBytes)
    if err != nil {
        fmt.Println("Error parsing the server's public key:", err)
        return
    }

    sharedSecret, err := privateKey.ECDH(serverPublicKey)
    if err != nil {
        fmt.Println("Error calculating the shared secret:", err)
        return
    }

    sharedSecretBuffer := memguard.NewBufferFromBytes(sharedSecret)
    defer sharedSecretBuffer.Destroy()

    block, err := aes.NewCipher(sharedSecret)
    if err != nil {
        fmt.Println("Error initializing AES cipher:", err)
        return
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        fmt.Println("Error initializing GCM mode:", err)
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
            fmt.Println("Error reading message:", err)
            return
        }
        decrypted, err := gcm.Open(nil, buf[:12], buf[12:n], nil)
        if err != nil {
            fmt.Println("Error decrypting message:", err)
            return
        }
        if string(decrypted) == ".QUIT" {
            conn.Close()
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
        os.Exit(0)
    }()

    for scanner.Scan() {
        message := scanner.Text()
        if message == ".QUIT" {
            nonce := make([]byte, 12)
            io.ReadFull(rand.Reader, nonce)
            encrypted := gcm.Seal(nil, nonce, []byte(message), nil)
            conn.Write(append(nonce, encrypted...))
            os.Exit(0)
        }
        nonce := make([]byte, 12)
        if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
            fmt.Println("Error generating nonce:", err)
            return
        }
        encrypted := gcm.Seal(nil, nonce, []byte(message), nil)
        conn.Write(append(nonce, encrypted...))
    }
}
