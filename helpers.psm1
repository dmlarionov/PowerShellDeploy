function Export-FunctionRemote {
<#
.SYNOPSIS
Exports function to the remote session
#>
    param (
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]
        $Session,

        [Parameter(Mandatory=$true)]
        [String]
        $FuncName
    )

    $funcBody = $(Get-Content function:\$FuncName)

    $funcDef = "function $FuncName {"
    $funcDef += $funcBody
    $funcDef += '}'

    Invoke-Command -Session $Session -ScriptBlock ([ScriptBlock]::Create($funcDef))
}

function Merge-Objects ($target, $source) {
<#
.SYNOPSIS
Update a target object with properties from the source object. Designed to be used with JSON transformations.
#>
    $source.psobject.Properties | ForEach-Object {
        If ($_.TypeNameOfValue -eq 'System.Management.Automation.PSCustomObject' -and $target."$($_.Name)" ) {
            Merge-Objects $target."$($_.Name)" $_.Value
        }
        Else {
            $target | Add-Member -MemberType $_.MemberType -Name $_.Name -Value $_.Value -Force
        }
    }
}

function Update-KnownHosts ([Parameter(Mandatory)][String] $hostname) {
<#
.SYNOPSIS
Update user's known_hosts file for SSH (add keys for provided hostname).
#>
    Write-Debug "Fetching keys for $hostname"
    # somewhy hash can be unstable, so we don't use -H parameter
    #$fetchedKeys = Invoke-Expression "ssh-keyscan -T 3 -H $hostname"
    $fetchedKeys = Invoke-Expression "ssh-keyscan -T 3 $hostname"    # TODO: hide STDERR output from appearing in log
    $userKnownHostsFile = ((Invoke-Expression "ssh -G localhost | select-string '^userknownhostsfile'") -split ' ')[1]
    $knownHosts = Get-Content $userKnownHostsFile
    ForEach ($fetchedKeyItem in $fetchedKeys) {
        If ($fetchedKeyItem -NotIn $knownHosts) {
            Write-Debug "Add known-hosts entry: $fetchedKeyItem"
            $fetchedKeyItem | Out-File -FilePath $userKnownHostsFile -Append
        }
        Else {
            Write-Debug "Key already present: $fetchedKeyItem"
        }
    }
}

function Get-CredentialFromBase64 {
<#
.SYNOPSIS
Return PSCredential object for base64-encoded login and password.
#>
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $loginBase64,

        [Parameter(Mandatory=$true)]
        [String]
        $unsecurePassworBase64
    )

    # check if vars were passed
    if ($null -eq $loginBase64) { throw "Login is null." }
    if ($null -eq $unsecurePassworBase64) { throw "Password is null." }

    # decode login and password (it has to be encoded in Jenkins pipeline for circumvention of credential masking)
    $login = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($loginBase64)).Trim()
    $unsecurePassword = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($unsecurePassworBase64)).Trim()

    # convert plain text to secure password
    $password = ConvertTo-SecureString $unsecurePassword -AsPlainText -Force

    New-Object System.Management.Automation.PSCredential($login, $password)
}

function Confirm-DotnetRuntimeWindows {
<#
.SYNOPSIS
Check if existing .Net Core shared framework can satisfy your requirements on Windows
#>
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $requiredVersion,

        [String]
        $frameworkName = "Microsoft.NETCore.App"
    )

    # find existing runtimes
    try {
        $existingRuntimes = (Get-ChildItem (Get-Command dotnet -ErrorAction SilentlyContinue).Path.Replace('dotnet.exe', "shared\$frameworkName")).Name
    }
    catch {
        throw "No .Net Core runtime found at the target machine! Get version '$requiredVersion' from https://dotnet.microsoft.com/download"
    }
    
    # check if it satisfies version requirement
    If ($requiredVersion.Split('.').Length -eq 2) {  # version format x.y
        If (($existingRuntimes -replace "(\d+)\.(\d+)\.(\d+)", '$1.$2') -NotContains $requiredVersion) {
            throw "The required .Net Core runtime version '$requiredVersion' is not found at the target machine! Get it from https://dotnet.microsoft.com/download"
        }
    }
    Else {                                          # version format x.y.z or x.y.z-previewV-mmmmm-nn / other
        If ($existingRuntimes -NotContains $requiredVersion) {
            throw "The required .Net Core runtime version '$requiredVersion' is not found at the target machine! Get it from https://dotnet.microsoft.com/download"
        }
    }
}

function Confirm-DotnetRuntimeLinux {
<#
.SYNOPSIS
Check if existing .Net Core shared framework can satisfy your requirements on Linux
#>
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $requiredVersion,

        [String]
        $frameworkName = "Microsoft.NETCore.App"
    )

    # find existing runtimes
    try {
        $existingRuntimes = (Get-ChildItem "/usr/share/dotnet/shared/$frameworkName").Name
    }
    catch {
        throw "No .Net Core runtime found at the target machine! Get version '$requiredVersion' from https://dotnet.microsoft.com/download"
    }
    
    # check if it satisfies version requirement
    If ($requiredVersion.Split('.').Length -eq 2) {  # version format x.y
        If (($existingRuntimes -replace "(\d+)\.(\d+)\.(\d+)", '$1.$2') -NotContains $requiredVersion) {
            throw "The required .Net Core runtime version '$requiredVersion' is not found at the target machine! Get it from https://dotnet.microsoft.com/download"
        }
    }
    Else {                                          # version format x.y.z or x.y.z-previewV-mmmmm-nn / other
        If ($existingRuntimes -NotContains $requiredVersion) {
            throw "The required .Net Core runtime version '$requiredVersion' is not found at the target machine! Get it from https://dotnet.microsoft.com/download"
        }
    }
}

function Grant-LogonAsServiceWindows {
<#
.SYNOPSIS
Grant permission for an account to log on as a service on Windows.
#>
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $login
    )

    # check parameters
    if([String]::IsNullOrEmpty($login)) {
        throw "No account is specified for granting log on as a service permission!"
    }
    
    # find sid
    $sid = $null
    try {
        $principal = new-object System.Security.Principal.NTAccount($login)
        $sid = $principal.Translate([System.Security.Principal.SecurityIdentifier]).Value.ToString()
    } catch {
        $sid = $null
    }

    if([String]::IsNullOrEmpty($sid)) {
        throw "Account '$login' is not found!"
    }

    Write-Debug "Checking the permission 'SeServiceLogonRight' for account '$login'."

    # get local security policy
    $policyFile = [System.IO.Path]::GetTempFileName()
    Invoke-Expression "secedit.exe /export /cfg '$($policyFile)'"
    $policyContent = Get-Content -Path $policyFile
    Remove-Item $policyFile # delete temporary file

    # get currently allowed SIDs
    $allowedSids = @()
    ForEach($line in $policyContent) {
        If( $line -Like "SeServiceLogonRight*") {
            $allowedSids = (($line.Split('=', [System.StringSplitOptions]::RemoveEmptyEntries))[1].Trim()).Split(',')
        }
    }

    # if sid or login (wihtout domain part) is not currently allowed
    If($allowedSids -NotContains $sid -and $allowedSids -NotContains ($login -replace "(\S*)\\(\S*)", '$2')) {
        Write-Debug "Granting the permission 'SeServiceLogonRight' for account '$login'."
        
        # get SIDs to allow (current + new)
        $sids = $allowedSids + @("*$sid")   # record format use asterisk before SID
        $policyContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeServiceLogonRight = $($sids -join ',')
"@
        $policyFile = [System.IO.Path]::GetTempFileName()
        $policyContent | Set-Content -Path $policyFile -Encoding Unicode -Force
        Invoke-Expression "secedit.exe /configure /db `"secedit.sdb`" /cfg `"$policyFile`" /areas USER_RIGHTS"
        Remove-Item $policyFile # delete temporary file #2
    }
}

function Add-UrlAclWindows {
<#
.SYNOPSIS
Add urlacl for http.sys
#>
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $login,

        [Parameter(Mandatory=$true)]
        [String] 
        $url
    )

    # pattern to match
    [regex] $pattern="^(?'proto'http|https):\/{2}(?'hostname'[0-9.\-A-Za-z]+)(?'port':\d{1,5})?(?'trailingslash'\/)?$"

    # check for match
    If (($m = $pattern.Match($url)).Success) {
        # rebuild URL (to be valid for netsh)
        $proto = $m.Groups['proto'].Value
        $hostname = $m.Groups['hostname'].Value
        $port = If ($m.Groups['port'].Success) { $m.Groups['port'].Value } else { '80' }
        $validUrl = "${proto}://${hostname}:${port}/"

        # add urlacl for http.sys
        if(-Not (Invoke-Expression "netsh.exe http show urlacl url=$validUrl" | Where-Object { $_ -match [regex]::Escape($validUrl) }))
        {
            Write-Debug -Message ('Granting {0} permission to listen on {1}.' -f $login, $validUrl)
            Invoke-Expression "netsh.exe http add urlacl url=$validUrl user='$login'" | Write-Debug
        }
    }
    Else {
        throw "This is not a valid URL: $url"
    }
}

function New-ServiceInstanceWindows {
<#
.SYNOPSIS
Create a new windows service instance.
#>
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $loginBase64,

        [Parameter(Mandatory=$true)]
        [String]
        $unsecurePassworBase64,

        [Parameter(Mandatory=$true)]
        [String]
        $targetService,

        [Parameter(Mandatory=$true)]
        [String] 
        $targetServiceBinPath,

        [String]
        $targetServiceDescription
    )

    # check if vars were passed
    if ($null -eq $loginBase64) { throw "Login is null." }
    if ($null -eq $unsecurePassworBase64) { throw "Password is null." }

    # TODO: add check - a login must be in MACHINENAME\USERNAME format

    # decode login and password (it has to be encoded in Jenkins pipeline for circumvention of credential masking)
    $login = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($loginBase64)).Trim()
    $unsecurePassword = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($unsecurePassworBase64)).Trim()

    # convert plain text to secure password
    $password = ConvertTo-SecureString $unsecurePassword -AsPlainText -Force

    # create PSCredential
    $credential = New-Object System.Management.Automation.PSCredential($login, $password)

    # deploy
    New-Service `
        -Name "$targetService" `
        -BinaryPathName "$targetServiceBinPath" `
        -DisplayName "$targetService" `
        -Description "$targetServiceDescription" `
        -StartupType Automatic `
        -Credential $credential `
        -ErrorAction Stop `
        -WarningAction Stop
}

function Start-ServiceInstanceWindows {
<#
.SYNOPSIS
Start a windows service instance and make sure it is started.
#>
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $targetService,
        
        [Parameter(Mandatory=$true)]
        [String] 
        $targetServiceBinPath,

        [Int]
        $wait = 3
    )

    $service = Get-Service -Name $targetService -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    
    # check for service to exists and not being running
    If ($null -eq $service) {
        throw "A service named '$targetService' was not found!"
    }
    If ($service.Status -eq "Running") {
        throw "The service '$targetService' is already running!"
    }

    # start
    $date = (Get-Date)
    $service | Start-Service -ErrorVariable StartError -ErrorAction SilentlyContinue
    Start-Sleep -Seconds $wait    # wait a little

    If ($StartError) {
        # write errors from EventLog, if failed
        Write-Warning "The possibly related application log records:"
        Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $date; } | ForEach-Object { 
            $values = $_.Properties | ForEach-Object { $_.Value }

            # write a new object with the detailed information
            [PSCustomObject]@{
                TimeCreated     = $_.TimeCreated
                ProviderName    = $_.ProviderName
                Id              = $_.Id
                Message         = $_.Message
                Details         = ($values -Join ' ')
            }
        }

        Write-Warning "The possibly related system log records:"
        Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $date; } | Format-List

        throw $StartError
    }

    # check for service status
    $service = Get-Service -Name $targetService -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    If (-Not $service.Status -eq "Running") {
        throw "The service '$targetService' is not running $wait seconds after the start attempt!"
    }

    # check for running executable
    If (@( Get-Process | Where-Object { $_.Path -eq $targetServiceBinPath } ).Count -lt 1) {
        throw "The service executable ($targetServiceBinPath) is not running!"
    }
}

function Stop-ServiceInstanceWindows {
<#
.SYNOPSIS
Stop a windows service instance and make sure it is stopped.
#>
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $targetService,
        
        [Parameter(Mandatory=$true)]
        [String] 
        $targetServiceBinPath,

        [Int]
        $wait = 3
    )

    $service = Get-Service -Name $targetService -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    
    # check for service to exists and is running, then stop it
    If ((-Not $null -eq $service) -And ($service.Status -eq "Running")) {
        $service | Stop-Service
        Start-Sleep -Seconds $wait
    }

    # check for service status
    $service = Get-Service -Name $targetService -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    If ((-Not $null -eq $service) -And ($service.Status -eq "Running")) {
        throw "Attempt to stop was unsuccessful!"
    }

    # check for running executable
    If (( Get-Process | Where-Object { $_.Path -eq $targetServiceBinPath } ).Count -gt 0) {
        throw "The service executable ($targetServiceBinPath) is still running!"
    }
}

function Invoke-SudoExpression {
<#
.SYNOPSIS
Invokes a sudo expression
#>
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $Command
    )
    $errFile = "/tmp/$($(New-Guid).Guid).err"
    Invoke-Expression "sudo ${Command} 2>${errFile}" -ErrorAction Stop
    $err = Get-Content $errFile -ErrorAction SilentlyContinue
    Remove-Item $errFile -ErrorAction SilentlyContinue
    If (-Not $null -eq $err)
    {
        throw $err
    }
}

function Invoke-SudoCommand {
<#
.SYNOPSIS
Invokes a sudo command in the remote session to Linux
#>
    param (
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]
        $Session,

        [Parameter(Mandatory=$true)]
        [String]
        $Command
    )
    Invoke-Command -Session $Session {
        Invoke-SudoExpression ${using:Command}
    }
}

function Remove-ServiceInstanceLinux {
<#
.SYNOPSIS
Remove a systemd service instance.
#>
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $targetService
    )
    If (Test-Path -Path "/usr/lib/systemd/system/${targetService}.service") {
        # remove unit file
        Invoke-SudoExpression "rm /usr/lib/systemd/system/${targetService}.service"

        # reload systemd manager configuration
        Invoke-SudoExpression "systemctl daemon-reload"
    }
}

function New-ServiceInstanceLinux {
<#
.SYNOPSIS
Create a new systemd service instance.
#>
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $targetUser,

        [Parameter(Mandatory=$true)]
        [String]
        $targetService,

        [Parameter(Mandatory=$true)]
        [String] 
        $targetServiceBinPath,

        [Parameter(Mandatory=$true)]
        [String]
        $targetFolder,

        [String]
        $targetServiceDescription
    )
    # unit configuration
    $tempUnitFile = [System.IO.Path]::GetTempFileName()
@"
[Unit]
Description=$targetServiceDescription
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$targetFolder
ExecStart=$targetServiceBinPath
ExecStop=/usr/bin/kill -s INT $MAINPID
User=$targetUser

[Install]
WantedBy=multi-user.target
"@ | Set-Content -Path $tempUnitFile -Encoding UTF8 -Force

    # move unit configuration into systemd directory
    Invoke-SudoExpression "mv $tempUnitFile /usr/lib/systemd/system/${targetService}.service"
    Invoke-SudoExpression "chown root:root /usr/lib/systemd/system/${targetService}.service"
    Invoke-SudoExpression "chmod 644 /usr/lib/systemd/system/${targetService}.service"

    # reload systemd manager configuration
    Invoke-SudoExpression "systemctl daemon-reload"
}

function Start-ServiceInstanceLinux {
<#
.SYNOPSIS
Start a systemd service instance and make sure it is started.
#>
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $targetService,
        
        [Parameter(Mandatory=$true)]
        [String] 
        $targetServiceBinPath,

        [Int]
        $wait = 3
    )

    # start
    $date = Invoke-Expression "date --rfc-3339=seconds | sed 's/+[0-9]*:[0-9]*$//g'"
    try {
        Invoke-SudoExpression "systemctl start ${targetService}.service"
        Start-Sleep -Seconds $wait    # wait a little
    }
    catch {
        Invoke-SudoExpression "journalctl -u ${targetService}.service -S '${date}'"
        throw $PSItem   # re-throw exception
    }

    # check for service status
    $activeState = Invoke-SudoExpression "systemctl is-active ${targetService}.service"
    If ($activeState -ne 'active') {
        Invoke-SudoExpression "journalctl -u ${targetService}.service -S '${date}'"
        throw "The service '$targetService' is not running $wait seconds after the start attempt! (active state is not 'active')"
    }

    # check for running executable
    If (@( Get-Process | Where-Object { $_.Path -eq $targetServiceBinPath } ).Count -lt 1) {
        Invoke-SudoExpression "journalctl -u ${targetService}.service -S '${date}'"
        throw "The service executable ($targetServiceBinPath) is not running!"
    }
}

function Stop-ServiceInstanceLinux {
<#
.SYNOPSIS
Stop a systemd service instance and make sure the service it is stopped.
#>
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $targetService,
        
        [Parameter(Mandatory=$true)]
        [String] 
        $targetServiceBinPath,

        [Int]
        $wait = 3
    )

    # check for active status
    $activeState = Invoke-SudoExpression "systemctl is-active ${targetService}.service"
    If ($activeState -eq 'active') {

        # stop
        $date = Invoke-Expression "date --rfc-3339=seconds | sed 's/+[0-9]*:[0-9]*$//g'"
        try {
            Invoke-SudoExpression "systemctl stop ${targetService}.service"
            Start-Sleep -Seconds $wait    # wait a little
        }
        catch {
            Invoke-SudoExpression "journalctl -u ${targetService}.service -S '${date}'"
            throw $PSItem   # re-throw exception
        }
    }

    # check for service status
    # TODO: check and throw "Attempt to stop was unsuccessful!"

    # check for running executable
    If (( Get-Process | Where-Object { $_.Path -eq $targetServiceBinPath } ).Count -gt 0) {
        throw "The service executable ($targetServiceBinPath) is still running!"
    }
}

Export-ModuleMember -Function `
    Export-FunctionRemote, Merge-Objects, Update-KnownHosts, Get-CredentialFromBase64, `
    Confirm-DotnetRuntimeWindows, Grant-LogonAsServiceWindows, Add-UrlAclWindows, New-ServiceInstanceWindows, Start-ServiceInstanceWindows, Stop-ServiceInstanceWindows, `
    Confirm-DotnetRuntimeLinux, Invoke-SudoExpression, Invoke-SudoCommand, Remove-ServiceInstanceLinux, New-ServiceInstanceLinux, Start-ServiceInstanceLinux, Stop-ServiceInstanceLinux
