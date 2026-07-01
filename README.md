# dnsrelay

DNS relay server for Windows, written in C.

## Target

- OS: Windows
- Compiler: MinGW-w64 gcc
- Language: C (C11)
- Socket library: Winsock2
- Default port: 53
- Default upstream DNS: 202.106.0.20

## Build

```bat
build.bat
```

Requires MinGW-w64 gcc in PATH.

## Run

```bat
dnsrelay.exe
dnsrelay.exe -d
dnsrelay.exe -dd
dnsrelay.exe -d 8.8.8.8 dnsrelay.txt
```

Administrator privileges may be required to bind port 53.

## Project structure

```
include/    Header files
src/        C source files
```
