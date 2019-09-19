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

Second, it have a notion of remote session, which is used for a command execution at a remote machine. You can orchestrate steps at a master machine (agent machine of CI / CD system), executing commands in sessions to target machines. Each session keeps context, so you can reuse remotely declared functions and variables (lets say - remote state) from its inception till the termination.

If you need to use some library code remotely you don't have to copy these libraries to remote machines, just run script blocks made of functions or declare functions remotely. I'll show you how.

# How to arrange a deployment?

You manage high-level steps like "build", "test", "deploy to stage", "deploy to prod" at the level of CI / CD pipeline and low-level steps of deployment process like "shutdown service", "delete service", "unpack software", "create service", "start service" at the level of a PowerShell deployment script.

The deployment script is going to be executed at least twice - for staging and for production. Regarding this, my recommendations are:

- Write a single script for staging and production deployment.
- Pass a parameter with the name of environment - "stage" or "prod" (or no value for production), because, probably, you may have to manage naming of things (services, deployment folders) by including "stage" suffix or, more universal, any provided environment name as a suffix.
- Pass everything about configuration (database connection strings, API keys e.t.c.) using environment variables. It's easy to do from CI / CD tool.

So, basically, your PowerShell script is going to be executed like:

1. For stage deployment: `pwsh -File ./tools/deploy-script-name.ps1 stage`
2. For production deployment: `pwsh -File ./tools/deploy-script-name.ps1`

Now, lets look at the example. Imagine you are deploying 2 services, one to Windows and another to Linux in staging and production environments. So, you have 4 boxes. Plus, you have Jenkins on its own Linux box.

First, install PowerShell Core everywhere (4 target boxes + Jenkins agent) and add it on target boxes to `sshd_config`:

```
Subsystem       powershell /usr/bin/pwsh -sshs -NoLogo -NoProfile
```

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

You have to create scripts (`./tools/...ps1`) that control low-level deployment steps which take their configurations through environment variables from `Jenkinsfile` this way:

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

Pattern shown above also demonstrates how to pass credentials to PowerShell. If you don't encode it somehow in PowerShell script you'll get it as series of asterisks (`****`). So, you have to:

```groovy
env.XXX_BASE64 = sh(script: 'set +x && echo $XXX | base64', , returnStdout: true).trim()
```

I invoke PowerShell script (see `sh "pwsh -File ..."`) inside of `withCredentials` for SSH, because a file with a key wouldn't exists outside of it (Jenkins manages that).

I put `helpers.psm1` in a directory (`./tools/` in my case) with scripts.

Script for Linux deployment usually looks like:

```powershell

```

Script for Windows deployment usually looks like:

```powershell

```

