# awesome-go-security

A dedicated place for cool golang security projects, frameworks, libraries, and software.
Pulled from collections such as [awesome-go](https://github.com/avelino/awesome-go) and [awesome-golang-security](https://github.com/guardrailsio/awesome-golang-security)


## Encryption

* [bencrypt](https://github.com/awgh/bencrypt) - Encryption Abstraction Layer and Utilities for ratnet .
* [holeysocks](https://github.com/audibleblink/HoleySocks) - Cross-Platform Reverse Socks Proxy in Go.
* [gokrb5](https://github.com/jcmturner/gokrb5) - Pure Go Kerberos library for clients and services.
* [go-tunnel](https://github.com/opencoff/go-tunnel) - TLS/SSL Tunnel - A modern STunnel replacement written in golang.
* [memguard](https://github.com/awnumar/memguard) - A pure Go library for handling sensitive values in memory.
* [nacl](https://github.com/kevinburke/nacl) - Go implementation of the NaCL set of API's.
* [passlib](https://github.com/hlandau/passlib) - Futureproof password hashing library.
* [saltpack](https://github.com/keybase/saltpack) - Modern crypto messaging format.
* [simple-scrypt](https://github.com/elithrar/simple-scrypt) - Scrypt package with a simple, obvious API and automatic cost calibration built-in.


## Packers / Obfuscators

* [gscript](https://github.com/gen0cide/gscript) - Framework to rapidly implement custom droppers for all three major operating systems
* [gobfuscate](https://github.com/unixpickle/gobfuscate) - Obfuscate Go binaries and packages
* [goupx](https://github.com/pwaller/goupx) - Fix golang compiled binaries on x86_64 so that they can be packed with UPX.
* [stegify](https://github.com/DimitarPetrov/stegify) - Go tool for LSB steganography, capable of hiding any file within an image.
* [obfs4](https://github.com/Yawning/obfs4) - Yawning Angel courtesy mirror of the obfourscator


## Private Key Infrastructure

* [acmetool](https://github.com/hlandau/acme) - ACME (Let's Encrypt) client tool with automatic renewal.
* [certigo](https://github.com/square/certigo) - A utility to examine and validate certificates in a variety of formats
* [CloudFlare SSL](https://github.com/cloudflare/cfssl) - CFSSL is CloudFlare's PKI/TLS swiss army knife. It is both a command line tool and an HTTP API server for signing, verifying, and bundling TLS certificates.


## SSH

* [ssh-vault](https://github.com/ssh-vault/ssh-vault) - encrypt/decrypt using ssh keys.
* [pam-ussh](https://github.com/uber/pam-ussh) - uber's ssh certificate pam module.


## File Transfer

* [dnd](https://github.com/0xcaff/dnd) - A web based drag and drop file transfer tool for sending files across the internet.
* [grab](https://github.com/cavaliercoder/grab) - Go package for managing file downloads.
* [onionbox](https://github.com/ciehanski/onionbox) - Send and recieve files through TOR


## Phishing

* [evilginx2](https://github.com/kgretzky/evilginx2) - Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies, allowing for the bypass of 2-factor authentication.
* [gophish](https://github.com/gophish/gophish) - Open-Source Phishing Toolkit
* [modlishka](https://github.com/drk1wi/Modlishka) - Modlishka. Reverse Proxy. Phishing NG.

## Command and Control

* [chashell](https://github.com/sysdream/chashell) - Chashell is a Go reverse shell that communicates over DNS.
* [GoAT](https://github.com/petercunha/GoAT) - GoAT (Golang Advanced Trojan) is a trojan that uses Twitter as a C&C server
* [gobot2](https://github.com/SaturnsVoid/GoBot2) - Second Version of The GoBot Botnet, But more advanced.
* [goredshell](https://github.com/ahhh/goredshell) -  A cross platform tool for verifying credentials and executing single commands
* [hershell](https://github.com/lesnuages/hershell) - Multiplatform reverse shell generator.
* [hideNsneak](https://github.com/rmikehodges/hideNsneak) - a CLI for ephemeral penetration testing
* [merlin](https://github.com/Ne0nd0g/merlin/) - Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
* [shellz](https://github.com/evilsocket/shellz) - shellz is a small utility to track and control your ssh, telnet, web and custom shells and tunnels.
* [squidshell](https://github.com/tomsteele/shellsquid) - A dynamic HTTP and DNS reverse proxy
* [ratnet](https://github.com/awgh/ratnet) - Ratnet is a prototype anonymity network for mesh routing and embedded scenarios.
* [Venom](https://github.com/Dliv3/Venom) - A Multi-hop Proxy for Penetration Testers Written in Go


## Web Framework Hardening

* [beego-security-headers](https://github.com/gosecguy/beego-security-headers) - Beego framework filter for easy security headers management.
* [goth](https://github.com/markbates/goth) - Provides a simple, clean, and idiomatic way to use OAuth and OAuth2. Handles multiple providers out of the box.
* [hsts](https://github.com/StalkR/hsts) - Go HTTP Strict Transport Security library
* [httpauth](https://github.com/goji/httpauth) - HTTP Authentication middleware.
* [jwt](https://github.com/robbert229/jwt) - Clean and easy to use implementation of JSON Web Tokens (JWT).
* [jwt](https://github.com/pascaldekloe/jwt) - Lightweight JSON Web Token (JWT) library.
* [nosurf](https://github.com/justinas/nosurf) - CSRF protection middleware for Go.
* [oauth2](https://github.com/golang/oauth2) - Successor of goauth2. Generic OAuth 2.0 package that comes with JWT, Google APIs, Compute Engine and App Engine support.
* [osin](https://github.com/openshift/osin) - Golang OAuth2 server library.
* [paseto](https://github.com/o1egl/paseto) - Platform-Agnostic Security Tokens implementation in GO (Golang)
* [gorilla/csrf](https://github.com/gorilla/csrf) - Provides Cross-Site Request Forgery (CSRF) prevention middleware for Go web applications & services.
* [gorilla/securecookie](https://github.com/gorilla/securecookie) - Encodes and decodes authenticated and optionally encrypted cookie values for Go web applications.
* [secure](https://github.com/unrolled/secure) -  Secure is an HTTP middleware for Go that facilitates most of your security needs for web applications.


## Web Application Testing

* [gobuster](https://github.com/OJ/gobuster) - Directory/file & DNS busting tool written in Go.
* [gofuz](https://github.com/braaaax/gofuzz) - Aims to reproduce wfuzz's functionality and versatility. Based on gobuster.
* [url2img](https://github.com/gen2brain/url2img) - HTTP server with API for capturing screenshots of websites.


## Network Scanners

* [bettercap](https://github.com/bettercap/bettercap) - The Swiss Army knife for 802.11, BLE and Ethernet networks reconnaissance and MITM attacks.
* [goddi](https://github.com/NetSPI/goddi) - goddi (go dump domain info) dumps Active Directory domain information
* [nextnet](https://github.com/hdm/nextnet) - nextnet is a pivot point discovery tool written in Go.
* [vulns](https://github.com/future-architect/vuls) - Vulnerability scanner for Linux/FreeBSD, agentless, written in Go
* [xray](https://github.com/evilsocket/xray) - XRay is a tool for recon, mapping and OSINT gathering from public networks.


## Network Analysis

* [goshark](https://github.com/sunwxg/goshark) - Package goshark use tshark to decode IP packet and create data struct to analyse packet.
* [gosnmp](https://github.com/soniah/gosnmp) - Native Go library for performing SNMP actions.
* [gopassivedns](https://github.com/Phillipmartin/gopassivedns) - PassiveDNS in Go.
* [nfp](https://github.com/awgh/nfp) - Network Finger Printer


## Exploit Development

* [binjection](https://github.com/Binject/binjection) - Injects additional machine instructions into various binary formats.
* [pwn](https://github.com/UlisseMini/pwn) - Pwntools for go!
* [monkey](https://github.com/bouk/monkey) - Monkey patching in Go
* [usercorn](https://github.com/lunixbochs/usercorn) - Dynamic binary analysis via platform emulation


## Detection Engines

* [fleet](https://github.com/kolide/fleet) - A flexible control server for osquery [fleets](https://kolide.com/fleet)
* [go-yara](https://github.com/hillu/go-yara) - Go Bindings for [YARA](https://github.com/plusvic/yara), the "pattern matching swiss knife for malware researchers (and everyone else)".
* [honeytrap](https://github.com/honeytrap/honeytrap) - Advanced Honeypot framework. 
* [malace](https://github.com/maliceio/malice) - VirusTotal Wanna Be - Now with 100% more Hipster
* [sgt](https://github.com/OktaSecurityLabs/sgt) - Osquery Mangement Server


## Chat Bots

* [alfred](https://github.com/demisto/alfred) - A Slack bot to add security info to messages containing URLs, hashes and IPs.
* [go-chat-bot](https://github.com/go-chat-bot/bot) - IRC, Slack & Telegram bot written in Go.
* [flottbot](https://github.com/target/flottbot) - A chatbot framework written in Go. All configurations are made in YAML.


## System Information

* [goinfo](https://github.com/matishsiao/goInfo) - get os information use golang
* [gopsutil](https://github.com/shirou/gopsutil) - psutil for golang


## General Post Exploitation

* [dlgs](https://github.com/gen2brain/dlgs) - Go cross-platform library for displaying dialogs and input boxes
* [goreddeath](https://github.com/ahhh/GoRedDeath) - Experimenting with destructive file attacks in Go.
* [goredloot](https://github.com/ahhh/GoRedLoot) - A tool to collect secrets (keys and passwords) and stage (compress and encrypt) them for exfiltration.
* [goredspy](https://github.com/ahhh/GoRedSpy) - Post exploitation desktop screensho / user monitoring tool


## Windows Specific

* [amsi](https://github.com/garethjensen/amsi) - Golang implementation of Microsoft Antimalware Scan Interface
* [com](https://github.com/garethjensen/com) - Go wrapper for Microsoft COM's IUnknown interface. 
* [go-execute-assembly](https://github.com/lesnuages/go-execute-assembly) - Allow a Go process to dynamically load .NET assemblies.
* [gosecretsdump](https://github.com/C-Sto/gosecretsdump) - Fast hash dumper for NTDS.dit files
* [taskmaster](https://github.com/capnspacehook/taskmaster) - Windows Task Scheduler Library for Go.


## MacOS Specific

* [damage](https://github.com/itchio/damage) - A toolkit for creating and manipulating DMGs


## Linux Specific

* [ftrace](https://github.com/evilsocket/ftrace) - Go library to trace Linux syscalls using the FTRACE kernel framework.
* [opensnitch](https://github.com/evilsocket/opensnitch) - OpenSnitch is a GNU/Linux port of the Little Snitch application firewall. 


## Data Parsing

* [cacador](https://github.com/sroberts/cacador) -  Indicator extractor of IOCs


## Static Code Analysis

* [go-diff](https://github.com/sergi/go-diff) - Diff, match and patch text in Go
* [gosec](https://github.com/securego/gosec) - Inspects source code for security problems by scanning the Go AST.
* [gometalinter](https://github.com/alecthomas/gometalinter) - Concurrently run Go lint tools and normalise their output.


## Assembly

* [avo](https://github.com/mmcloughlin/avo) - Generate x86 Assembly with Go
* [c2goasm](https://github.com/minio/c2goasm) - C to Go Assembly
* [shellcode](https://github.com/Binject/shellcode) - Shellcode library as a Go package

