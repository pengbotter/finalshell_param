finalshell的密码解析器
go重做了一份

编译：
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -gcflags "all=-N -l" -ldflags="-s -w" -o finalshell_linux main.go

执行：
./finalshell_linux --password eU15IxpjG1qmvvgmJGZFh9O5AIo0lHQgqHxJ6Hs2y4w=
