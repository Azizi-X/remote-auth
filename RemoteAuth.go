package RemoteAuth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"

	"sync"
	"time"

	http2 "net/http"

	"github.com/Azizi-X/utils/debug"
	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/buger/jsonparser"
	"github.com/gorilla/websocket"
)

const WSS_URL = "wss://remote-auth-gateway.discord.gg/?v=2"

var (
	DefaultClient, _ = tls_client.NewHttpClient(nil, tls_client.WithClientProfile(profiles.Chrome_131), tls_client.WithTimeoutSeconds(120))

	Headers = http.Header{
		"user-agent":   []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) discord-ptb/1.0.1156 Chrome/134.0.6998.205 Electron/35.3.0 Safari/537.36"},
		"content-type": []string{"application/json"},
	}

	ErrCaptchaRequired = errors.New("captcha required")
)

type RemoveOptions struct {
	OnFingerprint func(fingerprint string) error
	OnExchange    func(token string) error
}

type Remote struct {
	logger       *debug.Logger
	mu           sync.Mutex
	ctx          context.Context
	interval     int64
	timeout      int64
	privateKey   *rsa.PrivateKey
	pkixBytes    []byte
	heartbeater  *time.Ticker
	conn         *websocket.Conn
	dialer       *websocket.Dialer
	headers      http.Header
	heartbeatAck bool
	opts         RemoveOptions

	Fingerprint string
	Token       string
}

func (r *Remote) WriteJSON(data any) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.conn.WriteJSON(data)
}

func (r *Remote) cleanup() {
	r.heartbeater.Stop()
}

func (r *Remote) sendHeartbeat() {
	r.heartbeatAck = false
	r.conn.WriteJSON(map[string]string{
		"op": "heartbeat",
	})
}

func (r *Remote) newHeartbeater() {
	r.heartbeater = time.NewTicker(time.Duration(r.interval) * time.Millisecond)

	go func() {
		for {
			select {
			case <-r.heartbeater.C:
				r.sendHeartbeat()
			case <-r.ctx.Done():
				return
			}
		}
	}()
}

func (r *Remote) Close() {
	conn := r.conn
	r.conn = nil

	r.cleanup()

	if conn == nil {
		return
	}

	conn.Close()
}

func (r *Remote) _reconnect() error {
	r.Close()

	return r._connect()
}

func (r *Remote) _connect() error {
	if r.conn != nil {
		return r.Verbose("already connected")
	}

	if r.headers == nil {
		r.headers = http.Header{
			"Origin": []string{"https://discord.com"},
		}
	}

	if r.dialer == nil {
		r.dialer = &websocket.Dialer{
			HandshakeTimeout: 30 * time.Second,
		}
	}

	r.Verbose("[CONNECTING]")

	ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
	defer cancel()

	headers := make(http2.Header)
	maps.Copy(headers, r.headers)

	conn, _, err := r.dialer.DialContext(ctx, WSS_URL, headers)
	if err != nil {
		return r.Verbose("%s", err.Error())
	}

	r.Verbose("[CONNECTED] %s", WSS_URL)

	r.conn = conn

	return nil
}

func (r *Remote) handleErr(err error) bool {
	var code int
	var text string

	if close, ok := err.(*websocket.CloseError); ok {
		code = close.Code
		text = close.Text
	}

	r.Verbose("[%d] %s", code, text)

	if code == 4003 {
		return r._reconnect() == nil
	}

	return false
}

func (r *Remote) Connect() error {
	if err := r._connect(); err != nil {
		return err
	}

	defer r.Close()

	for r.ctx.Err() == nil {
		_, raw, err := r.conn.ReadMessage()

		if err != nil {
			if r.handleErr(err) {
				continue
			}
			return err
		}

		op, _ := jsonparser.GetUnsafeString(raw, "op")

		switch op {
		case "hello":
			r.interval, _ = jsonparser.GetInt(raw, "heartbeat_interval")
			r.timeout, _ = jsonparser.GetInt(raw, "timeout_ms")

			r.newHeartbeater()

			r.pkixBytes, err = x509.MarshalPKIXPublicKey(&r.privateKey.PublicKey)
			if err != nil {
				return err
			}

			r.WriteJSON(map[string]string{
				"op":                 "init",
				"encoded_public_key": base64.StdEncoding.EncodeToString(r.pkixBytes),
			})
		case "nonce_proof":
			encrypted, _ := jsonparser.GetString(raw, "encrypted_nonce")
			decoded, _ := base64.StdEncoding.DecodeString(encrypted)

			nonce, _ := rsa.DecryptOAEP(sha256.New(), nil, r.privateKey, decoded, nil)
			nonceProof := base64.RawURLEncoding.EncodeToString(nonce)

			r.WriteJSON(map[string]string{
				"op":    "nonce_proof",
				"nonce": nonceProof,
			})
		case "pending_remote_init":
			fingerprint, _ := jsonparser.GetString(raw, "fingerprint")

			hash := sha256.Sum256(r.pkixBytes)
			pkixFingerprint := base64.RawURLEncoding.EncodeToString(hash[:])

			if fingerprint != pkixFingerprint {
				r.Verbose("[FINGERPRINT] %s != %s", fingerprint, pkixFingerprint)
				if err := r._reconnect(); err != nil {
					return err
				}
			}

			r.Fingerprint = fingerprint

			if r.opts.OnFingerprint != nil {
				if err := r.opts.OnFingerprint(fingerprint); err != nil {
					return err
				}
			}

		case "pending_login":
			ticket, _ := jsonparser.GetString(raw, "ticket")

			token, err := r.exchange(ticket)

			if err != nil {
				return err
			}

			r.Token = token

			if r.opts.OnExchange != nil {
				if err := r.opts.OnExchange(token); err != nil {
					return err
				}
			}

			return nil
		case "heartbeat_ack":
			r.heartbeatAck = true
		}
	}

	return nil
}

func (r *Remote) exchange(ticket string) (token string, err error) {
	data, _ := json.Marshal(map[string]string{
		"ticket": ticket,
	})

	req, err := http.NewRequest("POST", "https://ptb.discord.com/api/v9/users/@me/remote-auth/login", bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}

	maps.Copy(req.Header, Headers)

	resp, err := DefaultClient.Do(req)
	if err != nil {
		return "", r.Verbose("%s", err.Error())
	}

	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	site_key, _ := jsonparser.GetString(body, "captcha_sitekey")

	if resp.StatusCode == 400 && site_key != "" {
		r.Verbose("[CAPTCHA] %d", resp.StatusCode)
		return "", ErrCaptchaRequired
	}

	if resp.StatusCode != 200 {
		return "", r.Verbose("status code: %d | %s", resp.StatusCode, string(body))
	}

	encrypted, _ := jsonparser.GetString(body, "encrypted_token")

	decoded, _ := base64.StdEncoding.DecodeString(encrypted)

	decrypted, _ := rsa.DecryptOAEP(sha256.New(), nil, r.privateKey, decoded, nil)

	return string(decrypted), nil
}

func (r *Remote) Verbose(msg string, formats ...any) error {
	if r.logger != nil {
		return r.logger.Verbose(msg, formats...)
	}

	return fmt.Errorf(msg, formats...)
}

func (r *Remote) WithDialer(dialer websocket.Dialer) *Remote {
	r.dialer = &dialer
	return r
}

func (r *Remote) WithHeaders(headers http.Header) *Remote {
	r.headers = headers
	return r
}

func (r *Remote) WithLogger(logger *debug.Logger) *Remote {
	r.logger = logger
	return r
}

func NewRemote(ctx context.Context, opts *RemoveOptions) *Remote {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	if opts == nil {
		opts = &RemoveOptions{}
	}

	return &Remote{
		ctx:        ctx,
		privateKey: privateKey,
		opts:       *opts,
	}
}
