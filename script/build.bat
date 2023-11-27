@echo off

cd ../


@rem Windows
go env -w GOOS=windows
@rem DockerCTL
cd ./src
go mod tidy
go build -o ../dist/domain.exe main.go
cd ../


@rem ----------------------------------------


@rem Linux
go env -w GOOS=linux
@rem DockerCTL
cd ./src
go mod tidy
go build -o ../dist/domain main.go
cd ../


cd ./script
