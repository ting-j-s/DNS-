@echo off
REM ── build.bat — Compile dnsrelay with MinGW-w64 gcc ────────────
REM
REM Usage:
REM   build.bat              Build debug
REM   build.bat release      Build optimized
REM   build.bat clean        Remove build artifacts

setlocal enabledelayedexpansion

if "%1"=="clean" (
    echo Cleaning build artifacts...
    del /q dnsrelay.exe 2>nul
    del /q src\*.o 2>nul
    echo Done.
    goto :eof
)

set CFLAGS=-Wall -Wextra -std=c11 -I include
set LDFLAGS=-lws2_32
set SRCS=src\main.c src\config.c src\logger.c src\platform_win.c src\udp_socket.c src\dns_packet.c src\dns_name.c src\resource_record.c src\resource_store.c src\transaction.c src\cache.c src\tcp_dns_client.c

if "%1"=="release" (
    set CFLAGS=%CFLAGS% -O2 -DNDEBUG
    echo [release build]
) else (
    set CFLAGS=%CFLAGS% -g -O0
    echo [debug build]
)

echo Compiling dnsrelay...
gcc %CFLAGS% %SRCS% %LDFLAGS% -o dnsrelay.exe

if %ERRORLEVEL% EQU 0 (
    echo Build successful: dnsrelay.exe
) else (
    echo Build FAILED.
    exit /b 1
)
