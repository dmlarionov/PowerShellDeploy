def DOTNET_RUNTIME='2.2'

def STAGE_DEPLOY_HOSTNAME='...'
def STAGE_RABBITMQ_HOSTNAME='...'
def STAGE_RABBITMQ_VHOST='stage'
def STAGE_DB_PGSQL_CONNECTION_TEMPLATE='Server=;Port=5432;Database=...;User Id=##USR##;Password=##PSW##;'
def STAGE_APP_INSIGHTS_INSTRUMENTATION_KEY='...'

def PROD_DEPLOY_HOSTNAME='...'
def PROD_RABBITMQ_HOSTNAME='...'
def PROD_RABBITMQ_VHOST='stage'
def PROD_DB_PGSQL_CONNECTION_TEMPLATE='Server=;Port=5432;Database=...;User Id=##USR##;Password=##PSW##;'
def PROD_APP_INSIGHTS_INSTRUMENTATION_KEY='...'

pipeline {
  agent {
    label 'linux && dotnet-2.2 && pwsh'
  }
  options {
    skipDefaultCheckout true
  }
  stages {
    stage('Configure') {
      steps {
        script {
          if (env.BRANCH_NAME == 'master') {
            currentBuild.displayName = "1.0.${BUILD_NUMBER}"
          }
          else {
            currentBuild.displayName = "non-master-build-${BUILD_NUMBER}"
          }
        }
      }
    }
    stage('Checkout') {
      steps {
        deleteDir()   /* clean up our workspace before checkout */
        checkout scm
      }
    }
    stage('Build') {
      steps {
        script {
          withCredentials(bindings: [usernamePassword(credentialsId: '...', passwordVariable: 'PAT', usernameVariable: 'PAT_USERNAME')]) {
            // env.DOTNET_CLI_TELEMETRY_OPTOUT = 1
            env.VSS_NUGET_EXTERNAL_FEED_ENDPOINTS = "{\"endpointCredentials\": [{\"endpoint\":\"https://MyOrg.pkgs.visualstudio.com/_packaging/MyFeed/nuget/v3/index.json\", \"username\":\"build\", \"password\":\"${PAT}\"}]}"
            sh 'dotnet build -c Release -r linux-x64 ./src/...'
            sh 'dotnet publish -c Release -r linux-x64 --no-build ./src/.../ -o ../../artifacts/...'
          }
        }
      }
    }
    stage('Deploy') {
      when {
        branch 'master'
      }
      stages {
        stage('Stage') {
          stages {
            stage('Service deploy') {
              options {
                lock('...-stage-deploy')
              }
              steps {
                script {
                  env.DOTNET_RUNTIME = DOTNET_RUNTIME
                  env.DEPLOY_HOSTNAME = STAGE_DEPLOY_HOSTNAME
                  env.RABBITMQ_HOSTNAME = STAGE_RABBITMQ_HOSTNAME
                  env.RABBITMQ_VHOST = STAGE_RABBITMQ_VHOST
                  env.DB_PGSQL_CONNECTION_TEMPLATE = STAGE_DB_PGSQL_CONNECTION_TEMPLATE
                  env.CACHE_REDIS_CONNECTION = STAGE_CACHE_REDIS_CONNECTION
                  env.APP_INSIGHTS_INSTRUMENTATION_KEY = STAGE_APP_INSIGHTS_INSTRUMENTATION_KEY
                  withCredentials([usernamePassword(credentialsId: '...', passwordVariable: 'RABBITMQ_PASSWD', usernameVariable: 'RABBITMQ_LOGIN')]) {
                    env.RABBITMQ_LOGIN_BASE64 = sh(script: 'set +x && echo $RABBITMQ_LOGIN | base64', , returnStdout: true).trim()
                    env.RABBITMQ_PASSWD_BASE64 = sh(script: 'set +x && echo $RABBITMQ_PASSWD | base64', , returnStdout: true).trim()
                  }
                  withCredentials([usernamePassword(credentialsId: '...', passwordVariable: 'DB_PGSQL_PASSWD', usernameVariable: 'DB_PGSQL_LOGIN')]) {
                    env.DB_PGSQL_LOGIN_BASE64 = sh(script: 'set +x && echo $DB_PGSQL_LOGIN | base64', , returnStdout: true).trim()
                    env.DB_PGSQL_PASSWD_BASE64 = sh(script: 'set +x && echo $DB_PGSQL_PASSWD | base64', , returnStdout: true).trim()
                  }
                  withCredentials(bindings: [sshUserPrivateKey(credentialsId: '...', keyFileVariable: 'DEPLOY_KEYFILE', usernameVariable: 'DEPLOY_LOGIN')]) {
                    env.DEPLOY_LOGIN_BASE64 = sh(script: 'set +x && echo $DEPLOY_LOGIN | base64', , returnStdout: true).trim()
                    env.DEPLOY_KEYFILE_BASE64 = sh(script: 'set +x && echo $DEPLOY_KEYFILE | base64', , returnStdout: true).trim()
                    sh "pwsh -File ./tools/deploy-service.ps1 stage"
                  }
                }
              }
            }
          }
        }
        stage('Prod') {
          input {
            message "Deploy service to production?"
            submitter 'Administrators'
          }
          stages {
            stage('Service deploy') {
              options {
                lock('...-prod-deploy')
              }
              steps {
                script {
                  env.DOTNET_RUNTIME = DOTNET_RUNTIME
                  env.DEPLOY_HOSTNAME = PROD_DEPLOY_HOSTNAME
                  env.RABBITMQ_HOSTNAME = PROD_RABBITMQ_HOSTNAME
                  env.RABBITMQ_VHOST = PROD_RABBITMQ_VHOST
                  env.DB_PGSQL_CONNECTION_TEMPLATE = PROD_DB_PGSQL_CONNECTION_TEMPLATE
                  env.CACHE_REDIS_CONNECTION = PROD_CACHE_REDIS_CONNECTION
                  env.APP_INSIGHTS_INSTRUMENTATION_KEY = PROD_APP_INSIGHTS_INSTRUMENTATION_KEY
                  withCredentials([usernamePassword(credentialsId: '...', passwordVariable: 'RABBITMQ_PASSWD', usernameVariable: 'RABBITMQ_LOGIN')]) {
                    env.RABBITMQ_LOGIN_BASE64 = sh(script: 'set +x && echo $RABBITMQ_LOGIN | base64', , returnStdout: true).trim()
                    env.RABBITMQ_PASSWD_BASE64 = sh(script: 'set +x && echo $RABBITMQ_PASSWD | base64', , returnStdout: true).trim()
                  }
                  withCredentials([usernamePassword(credentialsId: '...', passwordVariable: 'DB_PGSQL_PASSWD', usernameVariable: 'DB_PGSQL_LOGIN')]) {
                    env.DB_PGSQL_LOGIN_BASE64 = sh(script: 'set +x && echo $DB_PGSQL_LOGIN | base64', , returnStdout: true).trim()
                    env.DB_PGSQL_PASSWD_BASE64 = sh(script: 'set +x && echo $DB_PGSQL_PASSWD | base64', , returnStdout: true).trim()
                  }
                  withCredentials(bindings: [sshUserPrivateKey(credentialsId: '...', keyFileVariable: 'DEPLOY_KEYFILE', usernameVariable: 'DEPLOY_LOGIN')]) {
                    env.DEPLOY_LOGIN_BASE64 = sh(script: 'set +x && echo $DEPLOY_LOGIN | base64', , returnStdout: true).trim()
                    env.DEPLOY_KEYFILE_BASE64 = sh(script: 'set +x && echo $DEPLOY_KEYFILE | base64', , returnStdout: true).trim()
                    sh "pwsh -File ./tools/deploy-service.ps1"
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}