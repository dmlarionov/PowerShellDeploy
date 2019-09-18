# What is it?

The `helpers.psm1` is a PowerShell Module supporting deployment of software services to Linux and Windows, orchestrated by a build system.

I was doing my CI + CD in Jenkins, utilizing PowerShell everywhere, and I collected my own reusable functions in this helpers module. You can use it as is or as a code samples, if you are making yours.

## Features

- No matter what operating system is used (on build agent or on target system), because both (Linux and Windows) can run PowerShell.
- No matter what protocol (SSH or WinRM / PSRP) is used, but some batteries for SSH are in included.
- Manipulating configs.
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

Probably, you may want to reuse some deployment code for both Linux and Windows target machines. Or may be you need PowerShell to:

- Keep execution control at a built agent machine (check conditions, run steps in order), having consistent context (function definitions and variables) on a target machine between steps.
- Use a single session from begin to end (not connect to a target machine for each command batch).

Saying "check conditions, run steps in order" I mean low-level steps like "shutdown service", "delete service", "unpack software", "create service", "start service", not high-level steps which are CI / CD system controlled (build, test, deploy to stage, deploy to prod).

Yes, you may use Ansible, Chef and other tools designed for deploy. But, if for any reason you prefer to use your build agents for deployment or just like PowerShell, please, use this module.

# How to use it?

Imagine you are deploying 2 services, one to Windows and another to Linux in staging and production environments. So, you have 4 boxes.

First, install PowerShell (Core) everywhere (4 target boxes + build agent) and add it to `sshd_config`:

```
Subsystem       powershell /usr/bin/pwsh -sshs -NoLogo -NoProfile
```

Basically, your `Jenkinsfile` looks like this:

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

Probably, you want to use 2 scripts (in example above) - one for deployment to a Linux boxes and another for deployment to Windows, because staging and productions boxes are similar.

So, create scripts (`./tools/...ps1`) that control low-level deployment steps which take their configurations from environment variables and use it in `Jenkinsfile` stages like:

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

Pattern for `Jenkinsfile`, shown above, demonstrates how to pass credentials to PowerShell. If you don't encode it somehow in PowerShell you'll get it as series of asterisks (`****`). So, do:

```groovy
env.X_BASE64 = sh(script: 'set +x && echo $X | base64', , returnStdout: true).trim()
```

Invoke PowerShell script (see `sh "pwsh -File ..."`) inside of `withCredentials` for SSH, because a file with a key wouldn't exists outside of it (Jenkins manages it).

Script for Linux deployment, usually, looks like:

```powershell

```

Script for Windows deployment, usually, looks like:

```powershell

```

