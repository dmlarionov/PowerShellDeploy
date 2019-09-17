param (
    [String]
    $nonProdEnvName
)

$ErrorActionPreference = "Stop"
$DebugPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# Import helpers
Import-Module -Name $PSScriptRoot/helpers

#
# Basic setup
#
$name = "xxx"  # substitute the product name
$prod = [String]::IsNullOrEmpty($nonProdEnvName)
$srcLocalPath = "./src/$name"
$binLocalPath = "./artifacts/$name"
$tmpLocalPath = "./tmp/$($(New-Guid).Guid)"
$zipName = if ($prod) { "$name.zip" } else { "$name.$nonProdEnvName.zip" }
$zipLocalPath = "./artifacts/$zipName"
$targetFolder = if ($prod) { "C:\$name" } else { "C:\$name.$nonProdEnvName" }
$targetTempPath = "C:\Temp"
$targetService = if ($prod) { "$name" } else { "$name.$nonProdEnvName" }
$targetServiceBinPath = "$targetFolder\$name.exe"
$targetServiceDescription = if ($prod) { "Bla-Bla Service" } else { "Bla-Bla Service (non-production instance)" }  # substitute proper description
$deployHostname = $Env:DEPLOY_HOSTNAME
$dotnetRuntime = $Env:DOTNET_RUNTIME
$url = $Env:URL

# show the type of deployment
Write-Output "Deploying to $(If ($prod) { "production" } else { "'$nonProdEnvName'" }) environment."

#
# Making a temp copy of the artefact
#
Write-Debug "Making a temporary copy of the artefact."
If (Test-Path $tmpLocalPath) { Remove-Item $tmpLocalPath -Recurse -Force }
Copy-Item -Path $binLocalPath -Destination $tmpLocalPath -Recurse -Exclude @('appsettings.Production.json','appsettings.Development.json')

#
# Transforming the configuration
#
Write-Debug "Transforming the configuration."

# merge configs
$config = Get-Content "$srcLocalPath\appsettings.json" -raw | ConvertFrom-Json
$configProd = Get-Content "$srcLocalPath\appsettings.Production.json" -raw | ConvertFrom-Json
Merge-Objects $config $configProd

# configure RabbitMQ connection
$config.RabbitMQ.Connection.Username = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:RABBITMQ_LOGIN_BASE64)).trim()
$config.RabbitMQ.Connection.Password = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:RABBITMQ_PASSWD_BASE64)).trim()
$config.RabbitMQ.Connection.Hostname = $Env:RABBITMQ_HOSTNAME
$config.RabbitMQ.Connection.Vhost = $Env:RABBITMQ_VHOST

# configure DB connection
$conn = $Env:DB_SQLSERVER_CONNECTION_TEMPLATE
$conn = $conn.Replace("##USR##", [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:DB_SQLSERVER_LOGIN_BASE64)).trim())
$conn = $conn.Replace("##PSW##", [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:DB_SQLSERVER_PASSWD_BASE64)).trim())
$config.Db.SQLServer.Connection =  $conn

# configure cache connection
$conn = $Env:CACHE_SQLSERVER_CONNECTION_TEMPLATE
$conn = $conn.Replace("##USR##", [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:CACHE_SQLSERVER_LOGIN_BASE64)).trim())
$conn = $conn.Replace("##PSW##", [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:CACHE_SQLSERVER_PASSWD_BASE64)).trim())
$config.Cache.SQLServer.Connection =  $conn

# configure URL
$config.URL = $url

# configure application insights
$config.ApplicationInsights.InstrumentationKey = $Env:APP_INSIGHTS_INSTRUMENTATION_KEY

# write config
$config | ConvertTo-Json -depth 32| Set-Content "$tmpLocalPath/appsettings.json"

#
# Packing the artefact
#
Write-Debug "Packing the artefact."
Compress-Archive -Path "$tmpLocalPath/*" -DestinationPath $zipLocalPath -Force

#
# Configure SSH known_hosts
#
Update-KnownHosts $deployHostname

#
# Connect to the target machine
#
Write-Debug "Starting the remote session."
# due to the issue 4952 (https://github.com/PowerShell/PowerShell/issues/4952) copy over WinRM/PSRP Linux-to-Windows doesn't work!
#$c = Get-CredentialFromBase64 $Env:DEPLOY_LOGIN_BASE64 $Env:DEPLOY_PASSWD_BASE64
#$o = New-PSSessionOption -SkipCACheck -SkipCNCheck
#$s = New-PSSession -ComputerName $deployHostname -Credential $c -SessionOption $o -Authentication negotiate
# therefore, we use SSH
$login = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:DEPLOY_LOGIN_BASE64)).Trim()
$keyfile = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:DEPLOY_KEYFILE_BASE64)).Trim()
$s = New-PSSession -HostName $deployHostname -UserName $login -KeyFilePath $keyfile

#
# Define utility functions in the remote session
#
Write-Debug "Exporting functions"
Export-FunctionRemote -Session $s -FuncName "Get-CredentialFromBase64"

#
# Check runtime
#
Write-Debug "Checking the dotnet runtime."
Invoke-Command -Session $s -ArgumentList $dotnetRuntime -ScriptBlock ([ScriptBlock]::Create(${function:Confirm-DotnetRuntimeWindows}))

#
# Stop the existing service instance
#
Write-Debug "Stopping the service '$targetService' on the target machine (if running)."
Invoke-Command -Session $s -ArgumentList $targetService, $targetServiceBinPath, 30 -ScriptBlock ([ScriptBlock]::Create(${function:Stop-ServiceInstanceWindows}))

#
# Check for the target folder and clean-up
#
$folder = Invoke-Command -Session $s { Get-Item -Path $using:targetFolder -ErrorAction SilentlyContinue -WarningAction SilentlyContinue }
If (-Not $null -eq $folder) {
    Write-Debug "Removing the folder '$targetFolder' on the target machine."
    Invoke-Command -Session $s { Remove-Item -Path $using:targetFolder -Recurse -Force -ErrorAction Stop -WarningAction Stop }
}

#
# Copy the packed artefact
#
Write-Debug "Copying zip to the target machine into '$targetTempPath'."
# due to unknown issue content of wwwroot gets copied info the target folder (top-level) by recusive Copy-Item. Using of zip is anyway better.
#Copy-Item -Path "$binLocalPath/*" -Destination $targetFolder -ToSession $s -Recurse -Exclude @('appsettings.Production.json','appsettings.Development.json')
Copy-Item -Path $zipLocalPath -Destination $targetTempPath -ToSession $s

#
# Unpack the artefact
#
Write-Debug "Unpacking to the target folder ('$targetFolder')."
Invoke-Command -Session $s {
    $ProgressPreference = "SilentlyContinue"
    Expand-Archive -LiteralPath "$using:targetTempPath/$using:zipName" -DestinationPath $using:targetFolder 
}

#
# Remove existing service instance (if exists)
#
Write-Debug "Removing the service '$targetService' on the target machine (if exists)."
Invoke-Command -Session $s { Get-Service -Name $using:targetService -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Remove-Service }

#
# Check / grant log on as a service permission and URL ACL
#
$login = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:SERVICE_LOGIN_BASE64)).Trim()

Write-Debug "Checking / granting log on as a service permission for '$login'."
Invoke-Command -Session $s -ArgumentList $login -ScriptBlock ([ScriptBlock]::Create(${function:Grant-LogonAsServiceWindows}))

Write-Debug "Checking / adding a URL ACL for '$url' and '$login'."
Invoke-Command -Session $s -ArgumentList $login, $url -ScriptBlock ([ScriptBlock]::Create(${function:Add-UrlAclWindows}))

#
# Create the service instance
#
Write-Debug "Creating the service '$targetService' on the target machine."
Invoke-Command `
    -Session $s `
    -ArgumentList `
        $Env:SERVICE_LOGIN_BASE64, `
        $Env:SERVICE_PASSWD_BASE64, `
        $targetService, `
        $targetServiceBinPath, `
        $targetServiceDescription `
    -ScriptBlock ([ScriptBlock]::Create(${function:New-ServiceInstanceWindows}))

#
# Start the service instance
#
Write-Debug "Starting the service '$targetService' on the target machine."
Invoke-Command -Session $s -ArgumentList $targetService, $targetServiceBinPath -ScriptBlock ([ScriptBlock]::Create(${function:Start-ServiceInstanceWindows}))

#
# Tear down with the target machine
#
Write-Debug "Termination of the remote session."
Remove-PSSession -Session $s
