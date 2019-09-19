# What is it?

The `helpers.psm1` is a PowerShell Module supporting deployment of software services to Linux and Windows, orchestrated by a build system. I'm doing my CI + CD with Jenkins, utilizing PowerShell everywhere, and I collected my own reusable functions in this helpers module.

## Features

- No matter what operating system is used (on build agent or on target system), because both (Linux and Windows) can run PowerShell.
- No matter what protocol (SSH or WinRM / PSRP) is used, but some batteries for SSH are in included.
- Updating SSH known_hosts.
- Checking .NET runtime (for .NET application deployment).
- Exporting functions to a remote session.
- Creating credentials from login and password encoded in base-64 (for passing Jenkins Credentials).
- Granting log on as a service permission (for windows service deployment).
- Adding URL ACL to http.sys (for deployment of windows service, listening to HTTP).
- Creating windows service instance.
- Starting windows service with checking (for running process, status) and re-posting the possibly related records from application and system log (on target Windows machine) to output (build system log).
- Invoking sudo expressions and remote commands (on target Linux machine).
- Creating | removing and starting | stopping systemd services (on target Linux machine).
- Creating | removing and publishing | unpublishing firewalld services (on target Linux machine).

# Why to use it?

Yes, you may use Ansible, Chef and other tools designed for deploy. But, if you don't have time to learn advanced declarative tools and want to use scripted approach, welcome.

## Why PowerShell?

First, it runs on Windows and Linux, so you can reuse some code.

Second, it have a notion of remote session, which is used for a command execution at a remote machine. You can orchestrate steps at a master machine (agent machine of CI / CD system), executing commands in sessions to target machines. Each session keeps context, so you can reuse remotely declared functions and variables (lets say - remote state) from session inception till the termination.

If you need to use some library code remotely you don't have to copy these libraries to remote machines, just run script blocks made of functions or declare functions remotely. I'll show you how.

# How to arrange a deployment?

## General things

You manage high-level steps like "build", "test", "deploy to stage", "deploy to prod" at the level of CI / CD pipeline and low-level steps of deployment process like "shutdown service", "delete service", "unpack software", "create service", "start service" at the level of a PowerShell deployment script.

The deployment script is going to be executed at least twice - for staging and for production. Regarding this, my recommendations are:

- Write a single script for staging and production deployment.
- Pass a parameter with the name of environment - "stage" or no value for production, because you may have to manage naming of things (services, deployment folders) depending on environment.
- Pass everything about configuration (database connection strings, API keys e.t.c.) using environment variables.

So, basically, your PowerShell script is going to be executed like:

1. For stage deployment: `pwsh -File ./tools/deploy-script-name.ps1 stage`
2. For production deployment: `pwsh -File ./tools/deploy-script-name.ps1`

Now, lets look at the example. Imagine you are deploying 2 services, one to Windows and another to Linux in staging and production environments. So, you have 4 boxes. Plus, you have Jenkins on its own Linux box.

First, install PowerShell Core everywhere (4 target boxes + Jenkins agent) and add it on target boxes to `sshd_config`:

```
Subsystem       powershell /usr/bin/pwsh -sshs -NoLogo -NoProfile
```

Make sure you can login with SSH keys from your Jenkins Credentials to the target machines.

At high-level your `Jenkinsfile` looks like this:

```groovy
pipeline {
  stages {
    stage('Build') {
      steps {
        // ...
      }
    }
    stage('Test') {
      steps {
        // ...
      }
    }
    stage('Deploy') {
      when {
        branch 'master'
      }
      stages {
        stage('Stage') {
          stages {
            stage('Linux service name') {
              options {
                lock('linux-service-name-stage-deploy')
              }
              steps {
                // ...
              }
            }
            stage('Windows service name') {
              options {
                lock('windows-service-name-stage-deploy')
              }
              steps {
                // ...
              }
            }
          }
        }
        stage('Prod') {
          input {
            message "Deploy services to production?"
            submitter 'Administrators'
          }
          stages {
            stage('Linux service name') {
              options {
                lock('linux-service-name-prod-deploy')
              }
              steps {
                // ...
              }
            }
            stage('Windows service name') {
              options {
                lock('windows-service-name-prod-deploy')
              }
              steps {
                // ...
              }
            }
          }
        }
      }
    }
  }
}
```

You have to create 2 scripts (one for Windows service, another for Linux service) that control low-level deployment steps which take their configurations through environment variables from `Jenkinsfile` this way:

```groovy
stage('Linux service name') {
    options {
        lock('linux-service-name-stage-deploy')
    }
    steps {
        script {
            env.DEPLOY_HOSTNAME = ...
            env.RABBITMQ_HOSTNAME = ...
            env.RABBITMQ_VHOST = ...
            env.SQL_CONNECTION_TEMPLATE = ...
            ...
            withCredentials([usernamePassword(credentialsId: '...', passwordVariable: 'RABBITMQ_PASSWD', usernameVariable: 'RABBITMQ_LOGIN')]) {
                env.RABBITMQ_LOGIN_BASE64 = ...
                env.RABBITMQ_PASSWD_BASE64 = ...
            }
            withCredentials([usernamePassword(credentialsId: '...', passwordVariable: 'SQL_CONNECTION_PASSWD', usernameVariable: 'SQL_CONNECTION_LOGIN')]) {
                env.SQL_CONNECTION_LOGIN_BASE64 = ...
                env.SQL_CONNECTION_PASSWD_BASE64 = ...
            }
            ...
            withCredentials(bindings: [sshUserPrivateKey(credentialsId: '...', keyFileVariable: 'DEPLOY_KEYFILE', usernameVariable: 'DEPLOY_LOGIN')]) {
                env.DEPLOY_LOGIN_BASE64 = sh(script: 'set +x && echo $DEPLOY_LOGIN | base64', , returnStdout: true).trim()
                env.DEPLOY_KEYFILE_BASE64 = sh(script: 'set +x && echo $DEPLOY_KEYFILE | base64', , returnStdout: true).trim()
                sh "pwsh -File ./tools/deploy-linux-service-name.ps1 stage"
            }
        }
    }
}
```

Pattern shown above also demonstrates how to pass credentials to PowerShell. If you don't encode it somehow then in PowerShell script you'll get it as series of asterisks (`****`). So, you have to:

```groovy
env.SECRET_BASE64 = sh(script: 'set +x && echo $SECRET | base64', , returnStdout: true).trim()
```

In PowerShell I decode it back this way:

```powershell
$secret = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:SECRET_BASE64)).Trim()
```

I invoke PowerShell script (see `sh "pwsh -File ..."`) inside of `withCredentials` for SSH, because a file with a key wouldn't exists outside of it (Jenkins manages that).

I put `helpers.psm1` in a directory (`./tools/` in my case) with scripts.

## Linux service example

For sake of realism in our example lets assume that:

- The source code for Linux service is located at `./src/LinuxServiceName` (from root of the repository).
- The artifacts are built (earlier in pipeline) to `./artifacts` folder and `LinuxServiceName` located there is the folder we are going to deploy as a systemd service at the target Linux box.
- The service is written with .NET Core and have to be run with `/usr/bin/dotnet .../LinuxServiceName.dll` command. The required version of a shared framework is passed through `DOTNET_RUNTIME` environment variable.
- The target Linux machine name is passed through `DEPLOY_HOSTNAME` environment variable.
- The parameters related to RabbitMQ and database connection, that are passed through environment variables, should be added to `appsettings.json` which is the configuration file for the deployed service that have to be placed in its folder. Also, there are `appsettings.Production.json` in the source code folder which we want to merge into that settings.
- In the `SQL_CONNECTION_TEMPLATE` there are placeholders `##USR##` and `##PSW##` that have to be substituted with username and password (passed from Jenkins Credentials using other variables).
- We are going to deploy a systemd service that listens to some HTTP URL and have to open some TCP port using firewalld. So, lets get this through `FIREWALLD_PORT` and `URL` environment variables.

Script for Linux deployment may look like:

```powershell
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
$prod = [String]::IsNullOrEmpty($nonProdEnvName)

# vars related to local filesystem
$srcLocalPath = "./src/LinuxServiceName"
$binLocalPath = "./artifacts/LinuxServiceName"
$tmpLocalPath = "./tmp/$($(New-Guid).Guid)"
$zipName = if ($prod) { "LinuxServiceName.zip" } else { "LinuxServiceName-$nonProdEnvName.zip" }
$zipLocalPath = "./artifacts/$zipName"

# vars related to target machine filesystem, user, group, service
$targetFolder = if ($prod) { "/usr/local/linux-service-name" } else { "/usr/local/linux-service-name-$nonProdEnvName" }
$targetTempPath = "/tmp"
$targetService = if ($prod) { "linux-service-name" } else { "linux-service-name-$nonProdEnvName" }
$targetUser = $targetService
$targetGroup = $targetUser
$targetServiceBinPath = "/usr/bin/dotnet $targetFolder/LinuxServiceName.dll"
$targetServiceDescription = "Linux Service Example"

# some other vars
$deployHostname = $Env:DEPLOY_HOSTNAME
$dotnetRuntime = $Env:DOTNET_RUNTIME
$firewalldPort = $Env:FIREWALLD_PORT
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
$conn = $Env:SQL_CONNECTION_TEMPLATE
$conn = $conn.Replace("##USR##", [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:SQL_LOGIN_BASE64)).trim())
$conn = $conn.Replace("##PSW##", [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:SQL_PASSWD_BASE64)).trim())
$config.Db.SQL.Connection = $conn

# configure URL
$config.Kestrel.EndPoints.Http.Url = $url

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
# Remove the existing firewalld service
#
Write-Debug "Removing the firewalld service on the target machine."
Invoke-Command -Session $s -ArgumentList $targetService -ScriptBlock ([ScriptBlock]::Create(${function:Unpublish-FirewalldServiceLinux}))
Invoke-Command -Session $s -ArgumentList $targetService -ScriptBlock ([ScriptBlock]::Create(${function:Remove-FirewalldServiceLinux}))

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
    Invoke-SudoCommand -Session $s -Command "useradd -r -s /sbin/nologin -c '$targetServiceDescription' -U -M $targetUser"
}

#
# Make sure the folder is owned by the service user
#
Write-Debug "Altering the ownership and permissions to the target folder ('$targetFolder')."
Invoke-SudoCommand -Session $s -Command "chown -R ${targetUser}:${targetGroup} ${targetFolder}"
Invoke-SudoCommand -Session $s -Command "chmod -R 755 ${targetFolder}"    # rwxr-xr-x

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
# Create a firewalld service
#
Write-Debug "Creating the firewalld service on the target machine."
Invoke-Command -Session $s -ArgumentList $targetService, $firewalldPort, $targetServiceDescription -ScriptBlock ([ScriptBlock]::Create(${function:New-FirewalldServiceLinux}))
Invoke-Command -Session $s -ArgumentList $targetService -ScriptBlock ([ScriptBlock]::Create(${function:Publish-FirewalldServiceLinux}))

#
# Tear down with the target machine
#
Write-Debug "Termination of the remote session."
Remove-PSSession -Session $s
```

I didn't debug the code above, just sculpted it from existing projects. These scripts differ in the basic setup and in the transforming configuration sections, other sections are the same, they are just added or removed out of necessity.

## Windows service example

Lets make general assumptions the same as for the Linux example, but add some specific facts:

- We are going to deploy a Windows service written with the .NET Core that listens to some HTTP URL using HTTP.sys, not Kestrel Web-server. So, we have to configure URL ACL in HTTP.sys.

- We have to check for and grant logon as a service permission, because it's a Windows service that runs under some service user account.
- We pass login and password of service user account through `SERVICE_LOGIN_BASE64` and `SERVICE_PASSWD_BASE64` environment variables.

Script for Windows deployment may look like:

```powershell
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
$prod = [String]::IsNullOrEmpty($nonProdEnvName)

# vars related to local filesystem
$srcLocalPath = "./src/WindowsServiceName"
$binLocalPath = "./artifacts/WindowsServiceName"
$tmpLocalPath = "./tmp/$($(New-Guid).Guid)"
$zipName = if ($prod) { "WindowsServiceName.zip" } else { "WindowsServiceName-$nonProdEnvName.zip" }
$zipLocalPath = "./artifacts/$zipName"

# vars related to target machine filesystem, user, group, service
$targetFolder = if ($prod) { "C:\WindowsServiceName" } else { "C:\WindowsServiceName.$nonProdEnvName" }
$targetTempPath = "C:\Temp"
$targetService = if ($prod) { "WindowsServiceName" } else { "WindowsServiceName.$nonProdEnvName" }
$targetServiceBinPath = "$targetFolder\WindowsServiceName.exe"
$targetServiceDescription = "Windows Service Example"

# some other vars
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
$conn = $Env:SQL_CONNECTION_TEMPLATE
$conn = $conn.Replace("##USR##", [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:SQL_LOGIN_BASE64)).trim())
$conn = $conn.Replace("##PSW##", [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:SQL_PASSWD_BASE64)).trim())
$config.Db.SQL.Connection = $conn

# configure URL
$config.Url = $url

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
# due to the issue 4952 (https://github.com/PowerShell/PowerShell/issues/4952) copy over WinRM/PSRP Linux-to-Windows doesn't work!
#$c = Get-CredentialFromBase64 $Env:DEPLOY_LOGIN_BASE64 $Env:DEPLOY_PASSWD_BASE64
#$o = New-PSSessionOption -SkipCACheck -SkipCNCheck
#$s = New-PSSession -ComputerName $deployHostname -Credential $c -SessionOption $o -Authentication negotiate
# therefore, we use SSH
$login = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:DEPLOY_LOGIN_BASE64)).Trim()
$keyfile = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:DEPLOY_KEYFILE_BASE64)).Trim()
$s = New-PSSession -HostName $deployHostname -UserName $login -KeyFilePath $keyfile

#
# Check runtime
#
Write-Debug "Checking the dotnet runtime."
Invoke-Command -Session $s -ArgumentList $dotnetRuntime -ScriptBlock ([ScriptBlock]::Create(${function:Confirm-DotnetRuntimeWindows}))

#
# Stop the existing service instance
#
Write-Debug "Stopping the service '$targetService' on the target machine (if running)."
Invoke-Command -Session $s -ArgumentList $targetService, $targetServiceBinPath -ScriptBlock ([ScriptBlock]::Create(${function:Stop-ServiceInstanceWindows}))

#
# Remove the existing service instance
#
Write-Debug "Removing the service '$targetService' on the target machine (if exists)."
Invoke-Command -Session $s { Get-Service -Name $using:targetService -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Remove-Service }

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
# Check / grant log on as a service permission and URL ACL
#
$login = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:SERVICE_LOGIN_BASE64)).Trim()
$unsecurePasswd = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Env:SERVICE_PASSWD_BASE64)).Trim()

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
        $login, `
        $unsecurePasswd, `
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
```

I've left comment in the "Connect to the target machine" section with rationale why not to use WinRM / PSRP if your agent machine is a Linux box. So, use SSH. I think it is important.

Sometime you have to add extra wait timeout when stopping or starting Windows services as 3rd argument to `Stop-ServiceInstanceWindows` and `Start-ServiceInstanceWindows`. It can be important.

Most sections are slightly different from its Linux counterparts.

You can find a lot of solutions for PowerShell, so you can easily customize the code from the examples above for your need. I just documented how I do it and grouped most of reusable functions in the module.