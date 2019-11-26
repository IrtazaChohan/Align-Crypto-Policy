# Align-Crypto-Policy
Script to setup cryptography on servers - Written by Irtaza Chohan (www.lostintheclouds.net & https://github.com/IrtazaChohan/Align-Crypto-Policy)

TLS/SSL and Cryptography levels need to be adhered to and as best practice this script adjusts a server to meet this best practice.

This is a script that will setup latest cryptography standards on servers. It also disables any SSL standards that are known to be exploitable.

This has been tested on:

- Windows Server 2008
- Windows Server 2008 R2
- Windows Server 2012 R2
- Windows Server 2016
- Windows Server 2019

Note that registry backup is done as part of this script - the more you run this script the more backup it takes into new files without deleting older backups.
There are a number of parameters that this script accepts based on your requirment - please refer to Parameter section for information on this.

NOTES:
 1. You need to have Administrative rights on the server to run this script. 
 2. This script cannot be run remotely. You will need to copy the folder structure down locally to the server.
 3. Please remove the local copy of this script once completed.

The ciphers that get set are below (and this is the order as well):

TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521',
'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384',
'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521',
'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384',
'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256',
'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521',
'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384',
'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',
'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521',
'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384',
'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',
'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521',
'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384',
'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256',
'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521',
'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384',
'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256',
'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
'TLS_RSA_WITH_AES_256_GCM_SHA384',
'TLS_RSA_WITH_AES_128_GCM_SHA256',
'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
'TLS_RSA_WITH_AES_128_CBC_SHA256',
'TLS_RSA_WITH_AES_128_CBC_SHA'

The registry keys impacted are:

$CipherList = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"
$CipherOrderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
$SSL3 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"
$SSL3Server = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
$TLS10 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
$TLS11 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
$TLS12 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"