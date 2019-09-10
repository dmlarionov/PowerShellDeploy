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
$targetFolder = if ($prod) { "/usr/local/$name" } else { "/usr/local/$name-$nonProdEnvName" }
$targetTempPath = "/tmp"
$targetService = if ($prod) { "$name" } else { "$name-$nonProdEnvName" }
$targetUser = $targetService
$targetGroup = $targetUser
$targetServiceBinPath = "/usr/bin/dotnet $targetFolder/$name.dll"
$targetServiceDescription = if ($prod) { "Bla-Bla Service" } else { "Bla-Bla Service (non-production instance)" }  # substitute proper description
$deployHostname = $Env:DEPLOY_HOSTNAME
$dotnetRuntime = $Env:DOTNET_RUNTIME

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
$conn = $Env:DB_PGSQL_CONNECTION_TEMPLATE
$conn = $conn.Replace("##USR##", [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:DB_PGSQL_LOGIN_BASE64)).trim())
$conn = $conn.Replace("##PSW##", [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:DB_PGSQL_PASSWD_BASE64)).trim())
$config.Db.PostgreSQL.Connection = $conn

# configure cache connection
$config.Cache.Redis.Configuration = $Env:CACHE_REDIS_CONNECTION

# configure application insights
$config.ApplicationInsights.InstrumentationKey = $Env:APP_INSIGHTS_INSTRUMENTATION_KEY

# write config
$config | ConvertTo-Json -depth 32 | Set-Content "$tmpLocalPath/appsettings.json"

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
$login = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:DEPLOY_LOGIN_BASE64)).Trim()
$keyfile = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:DEPLOY_KEYFILE_BASE64)).Trim()
$s = New-PSSession -HostName $deployHostname -UserName $login -KeyFilePath $keyfile

#
# Define utility functions in the remote session
#
Write-Debug "Exporting functions"
Export-FunctionRemote -Session $s -FuncName "Invoke-SudoExpression"

#
# Check runtime
#
Write-Debug "Checking the dotnet runtime."
Invoke-Command -Session $s -ArgumentList $dotnetRuntime -ScriptBlock ([ScriptBlock]::Create(${function:Confirm-DotnetRuntimeLinux}))

#
# Stop the existing service instance
#
Write-Debug "Stopping the service '$targetService' on the target machine (if running)."
Invoke-Command -Session $s -ArgumentList $targetService, $targetServiceBinPath -ScriptBlock ([ScriptBlock]::Create(${function:Stop-ServiceInstanceLinux}))

#
# Remove the existing service instance
#
Write-Debug "Removing the service '$targetService' on the target machine (if exists)."
Invoke-Command -Session $s -ArgumentList $targetService -ScriptBlock ([ScriptBlock]::Create(${function:Remove-ServiceInstanceLinux}))

#
# Check for the target folder and clean-up
#
$folder = Invoke-Command -Session $s { Get-Item -Path $using:targetFolder -ErrorAction SilentlyContinue -WarningAction SilentlyContinue }
If (-Not $null -eq $folder) {
    Write-Debug "Removing the folder '$targetFolder' on the target machine."
    Invoke-SudoCommand -Session $s -Command "rm -rf ${targetFolder}"
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
Invoke-SudoCommand -Session $s -Command "unzip ${targetTempPath}/${zipName} -d ${targetFolder}"

#
# Check for user or create it
#
try {
    Write-Debug "Checking for user '$targetUser'."
    Invoke-SudoCommand -Session $s -Command "id -u $targetUser" | Out-Null
}
catch {
    Write-Debug "Creating the user '$targetUser' (with a group of the same name)."
    Invoke-SudoCommand -Session $s -Command "useradd -c '$targetServiceDescription' -U -M $targetUser"
}

#
# Create the service instance
#
Write-Debug "Creating the service '$targetService' on the target machine."
Invoke-Command `
    -Session $s `
    -ArgumentList `
        $targetUser, `
        $targetGroup, `
        $targetService, `
        $targetServiceBinPath, `
        $targetFolder, `
        $targetServiceDescription `
    -ScriptBlock ([ScriptBlock]::Create(${function:New-ServiceInstanceLinux}))

#
# Start the service instance
#
Write-Debug "Starting the service '$targetService' on the target machine."
Invoke-Command -Session $s -ArgumentList $targetService, $targetServiceBinPath -ScriptBlock ([ScriptBlock]::Create(${function:Start-ServiceInstanceLinux}))

#
# Tear down with the target machine
#
Write-Debug "Termination of the remote session."
Remove-PSSession -Session $s
