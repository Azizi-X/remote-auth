package RemoteAuth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Azizi-X/utils/debug"
	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/websocket"
	"github.com/buger/jsonparser"
)

var (
	ErrCaptchaRequired = errors.New("captcha required")
)

type RemoteOptions struct {
	OnFingerprint func(fingerprint string) error
	OnExchange    func(token string) error
	OnHTTP        func(method string, url string, data any) (*http.Response, []byte, error)
	OnSocket      func(ctx context.Context, u string) (*websocket.Conn, *http.Response, error)
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
	heartbeatAck bool
	opts         RemoteOptions
	url          string

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

	r.Verbose("[CONNECTING]")

	ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
	defer cancel()

	conn, _, err := r.opts.OnSocket(ctx, r.url)
	if err != nil {
		return r.Verbose("%s", err.Error())
	}

	r.Verbose("[CONNECTED] %s", r.url)

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
	data := map[string]string{
		"ticket": ticket,
	}

	request, body, err := r.opts.OnHTTP("POST", "/users/@me/remote-auth/login", data)
	if err != nil {
		return "", err
	}

	site_key, _ := jsonparser.GetString(body, "captcha_sitekey")
	if request.StatusCode == 400 && site_key != "" {
		r.Verbose("[CAPTCHA] %d", request.StatusCode)
		return "", ErrCaptchaRequired
	}

	if request.StatusCode != 200 {
		return "", r.Verbose("status code: %d | %s", request.StatusCode, string(body))
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

func (r *Remote) WithLogger(logger *debug.Logger) *Remote {
	r.logger = logger
	return r
}

func validateOptions(url string, opts RemoteOptions) {
	if opts.OnHTTP == nil {
		panic("[RemoteAuth] OnHTTP can not be nil")
	} else if opts.OnSocket == nil {
		panic("[RemoteAuth] ConnectSocket can not be nil")
	} else if url == "" {
		panic("[RemoteAuth] url can not be empty")
	}
}

func NewRemote(ctx context.Context, opts RemoteOptions, url string) *Remote {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	validateOptions(url, opts)

	return &Remote{
		ctx:        ctx,
		privateKey: privateKey,
		opts:       opts,
		url:        url,
	}
}
