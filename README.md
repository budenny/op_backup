# op_backup
Automated 1password backup

## ⚠️ Requires 1password CLI(op) to be installed on host

---
### How to build:
`go build`

### Usage:
- **op_backup** - backup 1password account into encrypted file(encrypted using 1password master password)
- **op_backup decrypt \<file\>** - decrypts backup file and print all 1password items in json format