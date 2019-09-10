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

function Merge-Objects ($Target, $Source) {
<#
.SYNOPSIS
Update a target object with properties from the source object. Designed to be used with JSON transformations.
#>
    $Source.psobject.Properties | ForEach-Object {
        If ($_.TypeNameOfValue -eq 'System.Management.Automation.PSCustomObject' -and $Target."$($_.Name)" ) {
            Merge-Objects $Target."$($_.Name)" $_.Value
        }
        Else {
            $Target | Add-Member -MemberType $_.MemberType -Name $_.Name -Value $_.Value -Force
        }
    }
}

function Update-KnownHosts ([Parameter(Mandatory)][String] $Hostname) {
<#
.SYNOPSIS
Update user's known_hosts file for SSH (add keys for provided hostname).
#>
    Write-Debug "Fetching keys for $Hostname"
    # somewhy hash can be unstable, so we don't use -H parameter
    #$fetchedKeys = Invoke-Expression "ssh-keyscan -T 3 -H $Hostname"
    $fetchedKeys = Invoke-Expression "ssh-keyscan -T 3 $Hostname"    # TODO: hide STDERR output from appearing in log
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
        $LoginBase64,

        [Parameter(Mandatory=$true)]
        [String]
        $UnsecurePassBase64
    )

    # check if vars were passed
    if ($null -eq $LoginBase64) { throw "Login is null." }
    if ($null -eq $UnsecurePassBase64) { throw "Password is null." }

    # decode login and password (it has to be encoded in Jenkins pipeline for circumvention of credential masking)
    $login = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($LoginBase64)).Trim()
    $unsecurePassword = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($UnsecurePassBase64)).Trim()

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
        $Version,

        [String]
        $FrameworkName = "Microsoft.NETCore.App"
    )

    # find existing runtimes
    try {
        $existingRuntimes = (Get-ChildItem (Get-Command dotnet -ErrorAction SilentlyContinue).Path.Replace('dotnet.exe', "shared\$FrameworkName")).Name
    }
    catch {
        throw "No .Net Core runtime found at the target machine! Get version '$Version' from https://dotnet.microsoft.com/download"
    }
    
    # check if it satisfies version requirement
    If ($Version.Split('.').Length -eq 2) {  # version format x.y
        If (($existingRuntimes -replace "(\d+)\.(\d+)\.(\d+)", '$1.$2') -NotContains $Version) {
            throw "The required .Net Core runtime version '$Version' is not found at the target machine! Get it from https://dotnet.microsoft.com/download"
        }
    }
    Else {  # version format x.y.z or x.y.z-previewV-mmmmm-nn / other
        If ($existingRuntimes -NotContains $Version) {
            throw "The required .Net Core runtime version '$Version' is not found at the target machine! Get it from https://dotnet.microsoft.com/download"
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
        $Version,

        [String]
        $FrameworkName = "Microsoft.NETCore.App"
    )

    # find existing runtimes
    try {
        $existingRuntimes = (Get-ChildItem "/usr/share/dotnet/shared/$FrameworkName").Name
    }
    catch {
        throw "No .Net Core runtime found at the target machine! Get version '$Version' from https://dotnet.microsoft.com/download"
    }
    
    # check if it satisfies version requirement
    If ($Version.Split('.').Length -eq 2) {  # version format x.y
        If (($existingRuntimes -replace "(\d+)\.(\d+)\.(\d+)", '$1.$2') -NotContains $Version) {
            throw "The required .Net Core runtime version '$Version' is not found at the target machine! Get it from https://dotnet.microsoft.com/download"
        }
    }
    Else {  # version format x.y.z or x.y.z-previewV-mmmmm-nn / other
        If ($existingRuntimes -NotContains $Version) {
            throw "The required .Net Core runtime version '$Version' is not found at the target machine! Get it from https://dotnet.microsoft.com/download"
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
        $Login
    )

    # check parameters
    if([String]::IsNullOrEmpty($Login)) {
        throw "No account is specified for granting log on as a service permission!"
    }
    
    # find sid
    $sid = $null
    try {
        $principal = new-object System.Security.Principal.NTAccount($Login)
        $sid = $principal.Translate([System.Security.Principal.SecurityIdentifier]).Value.ToString()
    } catch {
        $sid = $null
    }

    if([String]::IsNullOrEmpty($sid)) {
        throw "Account '$Login' is not found!"
    }

    Write-Debug "Checking the permission 'SeServiceLogonRight' for account '$Login'."

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
    If($allowedSids -NotContains $sid -and $allowedSids -NotContains ($Login -replace "(\S*)\\(\S*)", '$2')) {
        Write-Debug "Granting the permission 'SeServiceLogonRight' for account '$Login'."
        
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
        $Login,

        [Parameter(Mandatory=$true)]
        [String] 
        $Url
    )

    # pattern to match
    [regex] $pattern="^(?'proto'http|https):\/{2}(?'hostname'[0-9.\-A-Za-z]+)(?'port':\d{1,5})?(?'trailingslash'\/)?$"

    # check for match
    If (($m = $pattern.Match($Url)).Success) {
        # rebuild URL (to be valid for netsh)
        $proto = $m.Groups['proto'].Value
        $hostname = $m.Groups['hostname'].Value
        $port = If ($m.Groups['port'].Success) { $m.Groups['port'].Value } else { '80' }
        $validUrl = "${proto}://${hostname}:${port}/"

        # add urlacl for http.sys
        if(-Not (Invoke-Expression "netsh.exe http show urlacl url=$validUrl" | Where-Object { $_ -match [regex]::Escape($validUrl) }))
        {
            Write-Debug -Message ('Granting {0} permission to listen on {1}.' -f $Login, $validUrl)
            Invoke-Expression "netsh.exe http add urlacl url=$validUrl user='$Login'" | Write-Debug
        }
    }
    Else {
        throw "This is not a valid URL: $Url"
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
        $LoginBase64,

        [Parameter(Mandatory=$true)]
        [String]
        $UnsecurePassBase64,

        [Parameter(Mandatory=$true)]
        [String]
        $ServiceName,

        [Parameter(Mandatory=$true)]
        [String] 
        $ServiceBinPath,

        [String]
        $ServiceDescription
    )

    # create PSCredential
    $credential = Get-CredentialFromBase64($LoginBase64, $UnsecurePassBase64)

    # deploy
    New-Service `
        -Name "$ServiceName" `
        -BinaryPathName "$ServiceBinPath" `
        -DisplayName "$ServiceName" `
        -Description "$ServiceDescription" `
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
        $ServiceName,
        
        [Parameter(Mandatory=$true)]
        [String]
        $ServiceBinPath,

        [Int]
        $Wait = 3
    )

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    
    # check for service to exists and not being running
    If ($null -eq $service) {
        throw "A service named '$ServiceName' was not found!"
    }
    If ($service.Status -eq "Running") {
        throw "The service '$ServiceName' is already running!"
    }

    # start
    $date = (Get-Date)
    $service | Start-Service -ErrorVariable StartError -ErrorAction SilentlyContinue
    Start-Sleep -Seconds $Wait    # wait a little

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
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    If (-Not $service.Status -eq "Running") {
        throw "The service '$ServiceName' is not running $Wait seconds after the start attempt!"
    }

    # check for running executable
    If (@( Get-Process | Where-Object { $_.Path -eq $ServiceBinPath } ).Count -lt 1) {
        throw "The service executable ($ServiceBinPath) is not running!"
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
        $ServiceName,
        
        [Parameter(Mandatory=$true)]
        [String] 
        $ServiceBinPath,

        [Int]
        $Wait = 3
    )

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    
    # check for service to exists and is running, then stop it
    If ((-Not $null -eq $service) -And ($service.Status -eq "Running")) {
        $service | Stop-Service
        Start-Sleep -Seconds $Wait
    }

    # check for service status
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    If ((-Not $null -eq $service) -And ($service.Status -eq "Running")) {
        throw "Attempt to stop was unsuccessful!"
    }

    # check for running executable
    If (( Get-Process | Where-Object { $_.Path -eq $ServiceBinPath } ).Count -gt 0) {
        throw "The service executable ($ServiceBinPath) is still running!"
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
        $Expression
    )
    $errFile = "/tmp/$($(New-Guid).Guid).err"
    Invoke-Expression "sudo ${Expression} 2>${errFile}" -ErrorAction Stop
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
        $ServiceName
    )
    If (Test-Path -Path "/usr/lib/systemd/system/${ServiceName}.service") {
        # remove unit file
        Invoke-SudoExpression "rm /usr/lib/systemd/system/${ServiceName}.service"

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
        $ServiceUser,

        [Parameter(Mandatory=$true)]
        [String]
        $ServiceGroup,

        [Parameter(Mandatory=$true)]
        [String]
        $ServiceName,

        [Parameter(Mandatory=$true)]
        [String] 
        $ServiceBinPath,

        [Parameter(Mandatory=$true)]
        [String]
        $ServiceFolder,

        [String]
        $ServiceDescription
    )
    # unit configuration
    $tempUnitFile = [System.IO.Path]::GetTempFileName()
@"
[Unit]
Description=$ServiceDescription
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$ServiceFolder
ExecStart=$ServiceBinPath
ExecStop=/usr/bin/kill -s INT $MAINPID
User=$ServiceUser
Group=$ServiceGroup

[Install]
WantedBy=multi-user.target
"@ | Set-Content -Path $tempUnitFile -Encoding UTF8 -Force

    # move unit configuration into systemd directory
    Invoke-SudoExpression "mv $tempUnitFile /usr/lib/systemd/system/${ServiceName}.service"
    Invoke-SudoExpression "chown root:root /usr/lib/systemd/system/${ServiceName}.service"
    Invoke-SudoExpression "chmod 644 /usr/lib/systemd/system/${ServiceName}.service"

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
        $ServiceName,
        
        [Parameter(Mandatory=$true)]
        [String] 
        $ServiceBinPath,

        [Int]
        $Wait = 3
    )

    #$date = Invoke-Expression "date --rfc-3339=seconds | sed 's/+[0-9]*:[0-9]*$//g'"
    try {
        # start
        Invoke-SudoExpression "systemctl start ${ServiceName}"
        Start-Sleep -Seconds $Wait    # wait a little

        # check for service status
        $activeState = Invoke-SudoExpression "systemctl is-active ${ServiceName}"
        If ($activeState -ne 'active') {
            throw "The service '$ServiceName' is not running $Wait seconds after the start attempt! (active state is not 'active')"
        }

        # check for running executable
        # FIXME: doesn't work for dlls started with dotnet command
        # If (@( Get-Process | Where-Object { $_.Path -eq $ServiceBinPath } ).Count -lt 1) {
        #     throw "The service executable ($ServiceBinPath) is not running!"
        # }
    }
    catch {
        #Invoke-SudoExpression "journalctl -u ${ServiceName} -S '${date}'"
        Invoke-SudoExpression "systemctl status ${ServiceName}"
        throw $PSItem   # re-throw exception
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
        $ServiceName,
        
        [Parameter(Mandatory=$true)]
        [String] 
        $ServiceBinPath,

        [Int]
        $Wait = 3
    )

    # check for active status
    $activeState = Invoke-SudoExpression "systemctl is-active ${ServiceName}"
    If ($activeState -eq 'active') {
        #$date = Invoke-Expression "date --rfc-3339=seconds | sed 's/+[0-9]*:[0-9]*$//g'"
        try {
            # stop
            Invoke-SudoExpression "systemctl stop ${ServiceName}"
            Start-Sleep -Seconds $Wait    # wait a little

            # check for service status
            # TODO: check and throw "Attempt to stop was unsuccessful!"

            # check for running executable
            # FIXME: doesn't work for dlls started with dotnet command
            # If (( Get-Process | Where-Object { $_.Path -eq $ServiceBinPath } ).Count -gt 0) {
            #     throw "The service executable ($ServiceBinPath) is still running!"
            # }
        }
        catch {
            #Invoke-SudoExpression "journalctl -u ${ServiceName} -S '${date}'"
            Invoke-SudoExpression "systemctl status ${ServiceName}"
            throw $PSItem   # re-throw exception
        }
    }
}

Export-ModuleMember -Function `
    Export-FunctionRemote, Merge-Objects, Update-KnownHosts, Get-CredentialFromBase64, `
    Confirm-DotnetRuntimeWindows, Grant-LogonAsServiceWindows, Add-UrlAclWindows, New-ServiceInstanceWindows, Start-ServiceInstanceWindows, Stop-ServiceInstanceWindows, `
    Confirm-DotnetRuntimeLinux, Invoke-SudoExpression, Invoke-SudoCommand, Remove-ServiceInstanceLinux, New-ServiceInstanceLinux, Start-ServiceInstanceLinux, Stop-ServiceInstanceLinux
