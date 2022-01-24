package main

import (
	"github.com/go-facegit/facegit-ssh/ssh"
)

func main() {
	ssh.Listen(ssh.DefaultConfig.HOST, ssh.DefaultConfig.SSH_PORT, ssh.DefaultConfig.SSH_SERVER_CIPHERS, ssh.DefaultConfig.SSH_SERVER_MACS)
}
