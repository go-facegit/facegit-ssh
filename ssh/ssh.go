package ssh

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/unknwon/com"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	HOST               string
	SSH_PORT           int
	SSH_SERVER_MACS    []string
	SSH_SERVER_CIPHERS []string

	GitBinPath  string
	ProjectRoot string
}

var (
	DefaultConfig = Config{
		SSH_PORT:           8722,
		HOST:               "0.0.0.0",
		GitBinPath:         "/usr/local/bin/git",
		SSH_SERVER_CIPHERS: []string{"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "arcfour256", "arcfour128"},
		SSH_SERVER_MACS:    []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-256", "hmac-sha1"},
	}
)

func init() {
	dir, err := os.Getwd()
	if err == nil {
		DefaultConfig.ProjectRoot = fmt.Sprintf("%s/repo", dir)
	}
}

func cleanCommand(cmd string) string {
	i := strings.Index(cmd, "git")
	if i == -1 {
		return cmd
	}
	return cmd[i:]
}

func handleServerConn(keyID string, chans <-chan ssh.NewChannel) {
	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		ch, reqs, err := newChan.Accept()
		if err != nil {
			log.Printf("Error accepting channel: %v", err)
			continue
		}

		go func(in <-chan *ssh.Request) {
			defer func() {
				_ = ch.Close()
			}()
			for req := range in {
				payload := cleanCommand(string(req.Payload))
				switch req.Type {
				case "env":
					var env struct {
						Name  string
						Value string
					}
					if err := ssh.Unmarshal(req.Payload, &env); err != nil {
						log.Printf("SSH: Invalid env payload %q: %v", req.Payload, err)
						continue
					}

					if env.Name == "" || env.Value == "" {
						log.Printf("SSH: Invalid env arguments: %+v", env)
						continue
					}

					_, stderr, err := com.ExecCmd("env", fmt.Sprintf("%s=%s", env.Name, env.Value))
					if err != nil {
						log.Printf("env: %v - %s", err, stderr)
						return
					}

				case "exec":
					cmdName := strings.TrimLeft(payload, "'()")
					log.Printf("SSH: Payload: %v", cmdName)

					args := []string{"serv", "key-" + keyID, "--config=" + "/"}
					log.Printf("SSH: Arguments: %v", args)
					cmd := exec.Command("./", args...)
					cmd.Env = append(os.Environ(), "SSH_ORIGINAL_COMMAND="+cmdName)

					stdout, err := cmd.StdoutPipe()
					if err != nil {
						log.Printf("SSH: StdoutPipe: %v", err)
						return
					}
					stderr, err := cmd.StderrPipe()
					if err != nil {
						log.Printf("SSH: StderrPipe: %v", err)
						return
					}
					input, err := cmd.StdinPipe()
					if err != nil {
						log.Printf("SSH: StdinPipe: %v", err)
						return
					}

					// FIXME: check timeout
					if err = cmd.Start(); err != nil {
						log.Printf("SSH: Start: %v", err)
						return
					}

					_ = req.Reply(true, nil)
					go func() {
						_, _ = io.Copy(input, ch)
					}()
					_, _ = io.Copy(ch, stdout)
					_, _ = io.Copy(ch.Stderr(), stderr)

					if err = cmd.Wait(); err != nil {
						log.Printf("SSH: Wait: %v", err)
						return
					}

					_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
					return
				default:
				}
			}
		}(reqs)
	}
}

func portListen(config *ssh.ServerConfig, host string, port int) {

	link := fmt.Sprintf("%s:%d", host, port)
	fmt.Println(link)
	listener, err := net.Listen("tcp", link)
	if err != nil {
		log.Printf("Failed to start SSH server: %v", err)
	}
	for {
		// Once a ServerConfig has been configured, connections can be accepted.
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("SSH: Error accepting incoming connection: %v", err)
			continue
		}

		// Before use, a handshake must be performed on the incoming net.Conn.
		// It must be handled in a separate goroutine,
		// otherwise one user could easily block entire loop.
		// For example, user could be asked to trust server key fingerprint and hangs.
		go func() {
			log.Printf("SSH: Handshaking for %s", conn.RemoteAddr())
			sConn, chans, reqs, err := ssh.NewServerConn(conn, config)

			if err != nil {
				if err == io.EOF {
					log.Printf("SSH: Handshaking was terminated: %v", err)
				} else {
					log.Printf("SSH: Error on handshaking: %v", err)
				}
				return
			}

			log.Printf("SSH: Connection from %s (%s)", sConn.RemoteAddr(), sConn.ClientVersion())
			// The incoming Request channel must be serviced.
			go ssh.DiscardRequests(reqs)
			go handleServerConn(sConn.Permissions.Extensions["key-id"], chans)
		}()
	}
}

func Listen(host string, port int, ciphers, macs []string) {
	config := &ssh.ServerConfig{
		Config: ssh.Config{
			Ciphers: ciphers,
			MACs:    macs,
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {

			fmt.Println(key)
			fmt.Println(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
			// pkey, err := db.SearchPublicKeyByContent(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
			// if err != nil {
			// 	log.Printf("SearchPublicKeyByContent: %v", err)
			// 	return nil, err
			// }
			return &ssh.Permissions{Extensions: map[string]string{"key-id": com.ToStr(1)}}, nil
		},
	}

	fmt.Println("start ssh service")
	portListen(config, host, port)
}
