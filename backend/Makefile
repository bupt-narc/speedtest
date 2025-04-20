all: build

build-frontend:
	make -C frontend

build: build-frontend
	CGO_ENABLED=0 go build -gcflags="all=-N -l" -ldflags="-s -w" -o speedtest bin/main.go

clean:
	make -C frontend clean
	$(RM) speedtest

container: build-frontend
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -gcflags="all=-N -l" -ldflags="-s -w" -o speedtest bin/main.go
	docker build . -t vcs.bupt-narc.cn/mtd/speedtest
