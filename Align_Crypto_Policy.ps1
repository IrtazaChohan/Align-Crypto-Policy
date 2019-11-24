# #############################################################################
# NAME: Align_Cryto_Policy.ps1
# 
# AUTHOR:  Irtaza Chohan
# 
# COMMENT:  Script to align cryptography across baseline.
#           This script will disable TLS 1.0 and set the cipher order as per below
#
# VERSION HISTORY
# 1.0 <DATE> Initial Version.
# 2.0 24/11/2019 Updated script to accept parameters to meet various configurations
# #############################################################################

[CmdletBinding()]
param (
    
        [Parameter(Mandatory=$True,
        HelpMessage="Please view the help for this script; type in ""help Align_Crypto_Policy.ps1""")]
        [string]$LogFilePath,
        [Parameter(Mandatory=$true)]
        [string]$RegistryExportPath,
        [switch]$SetDefaultCiphers,
        [switch]$DisableSSLv3Client,
        [switch]$DisableSSLv3Server,
        [switch]$EnableSSLv1,
        [switch]$EnableSSLv11,
        [switch]$EnableSSLv12
)

function writelog([string]$result, [string]$logfile) {
    try {
        $objlogfile = new-object system.io.streamwriter("$LogFilePath\$logfile", [System.IO.FileMode]::Append)
        $objlogfile.writeline("$((Get-Date).ToString()) : $result")
        write-host (Get-Date).ToString() " : $result"  -foregroundcolor yellow
        $objlogfile.close()
    } catch [Exception] {
        Write-Host $result -foregroundcolor red
        $error.clear()
   }
} 

$log = "Align_Cryto_Policy.log"

$ScriptName = $MyInvocation.MyCommand.Name

writelog "==============================================" $log
writelog "$ScriptName Script Started" $log
writelog "----------------------------------------------" $log

writelog "Script to align cryptography on server" $log

writelog "Exporting registry key's to $($RegistryExportPath)" $log

$date = Get-Date -format HH.mm.ss.dd.MM.yyyy

Reg export "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration" $RegistryExportPath\Cryptographyexportedkey$($date).reg
Reg export "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders" $RegistryExportPath\SecurityProvidersexportedkey$($date).reg

$CipherList = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"
$CipherOrderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
$SSL3 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"
$SSL3Server = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
$TLS10 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
$TLS11 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
$TLS12 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"

$CipherListContext = "`nTLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521
`nTLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384 
`nTLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521 
`nTLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384 
`nTLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256 
`nTLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521 
`nTLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384 
`nTLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256 
`nTLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521 
`nTLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384 
`nTLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256 
`nTLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521 
`nTLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384 
`nTLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256 
`nTLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521 
`nTLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384 
`nTLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256 
`nTLS_DHE_RSA_WITH_AES_128_GCM_SHA256
`nTLS_RSA_WITH_AES_256_GCM_SHA384 
`nTLS_RSA_WITH_AES_128_GCM_SHA256 
`nTLS_DHE_RSA_WITH_AES_256_CBC_SHA 
`nTLS_DHE_RSA_WITH_AES_128_CBC_SHA 
`nTLS_RSA_WITH_AES_128_CBC_SHA256 
`nTLS_RSA_WITH_AES_128_CBC_SHA"

$CipherOrder = @('TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521',
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
)


$cipherSuites = [string]::join(',', $CipherOrder)

#-----------------------------------------------------------------------------
If($SetDefaultCiphers){
    Try {
    #Set default ciphers on server
    writelog "Setting default ciphers on server" $log
    Set-ItemProperty -Path $CipherList -Name 'Functions' -Value $CipherListContext -Force | Out-Null -ErrorAction Stop
    }
    Catch {

    writelog "ERROR: $Error[0]" $log 
    $Error[0] 
    Exit -1
    }

    #-----------------------------------------------------------------------------

    Try{
    #Set Cipher Order to enable Forward Secrecy
    writelog "Setting Cipher Order to enable Forward Secrecy" $log
    $pathCheck = test-path -Path $CipherOrderPath

    if($pathcheck -eq $False) 
        {
            writelog "Path for Policy does not exist - creating path.." $log
            New-Item -Path $CipherOrderPath -Force | Out-Null -ErrorAction Stop
        }

    New-ItemProperty -path $CipherOrderPath -name 'Functions' -value $cipherSuites -PropertyType 'String' -Force | Out-Null -ErrorAction Stop
    }
    Catch {

    writelog "ERROR: $Error[0]" $log 
    $Error[0] 
    Exit -1

    }

}
#-------------------------------------------------------------------------------

If($DisableSSLv3Client){
    #Disable SSL 3.0 Client
    New-Item $SSL3 -Force | Out-Null -ErrorAction Stop
    New-ItemProperty -Path $SSL3 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null -ErrorAction Stop
    New-ItemProperty -Path $SSL3 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null -ErrorAction Stop
    writelog "SSL 3.0 Client now disabled" $log
}

#-------------------------------------------------------------------------------
If($DisableSSLv3Server){
    #Disable SSL 3.0 Server
    New-Item $SSL3Server -Force | Out-Null -ErrorAction Stop
    New-ItemProperty -Path $SSL3Server -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null -ErrorAction Stop
    New-ItemProperty -Path $SSL3Server -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null -ErrorAction Stop
    writelog "SSL 3.0 Server now disabled" $log
}
#--------------------------------------------------------------------------------
If($EnableSSLv1){
    #Enable SSL 1.0
    writelog "Ensuring TLS 1.0 is enabled" $log
    New-Item $TLS10 -Force | Out-Null -ErrorAction SilentlyContinue
    New-ItemProperty -Path $TLS10 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null -ErrorAction SilentlyContinue
    New-ItemProperty -Path $TLS10 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null -ErrorAction SilentlyContinue
}

If($EnableSSLv11){
    #Enable SSL 1.1
    writelog "Ensuring TLS 1.1 is enabled" $log
    New-Item $TLS11 -Force | Out-Null -ErrorAction SilentlyContinue
    New-ItemProperty -Path $TLS11 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null -ErrorAction SilentlyContinue
    New-ItemProperty -Path $TLS11 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null -ErrorAction SilentlyContinue
}

If($EnableSSLv12){
    #Enable SSL 1.2
    writelog "Ensuring TLS 1.2 is enabled" $log
    New-Item $TLS12 -Force | Out-Null -ErrorAction SilentlyContinue
    New-ItemProperty -Path $TLS12 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null -ErrorAction SilentlyContinue
    New-ItemProperty -Path $TLS12 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null -ErrorAction SilentlyContinue
}

writelog "$ScriptName Script ended" $log
writelog "==============================================" $log

#>