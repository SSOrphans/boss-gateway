node {
    withEnv(['serviceName=boss-gateway',"commitHash=${sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()}"]) {
        stage('Checkout') {
            echo "Checking out $serviceName"
            checkout scm
            sh 'git submodule update --init'

        }
        stage('Build') {
            withMaven(jdk: 'openjdk-11') {
                echo "Building $serviceName with maven"
                sh 'mvn clean package'
            }
        }
        stage('Quality Analysis') {
            withCredentials([string(credentialsId: 'sonar-token', variable: 'sonartoken')]) {
                withMaven(jdk: 'openjdk-11') {
                    echo "Performing Quality Analysis for $serviceName"
                    sh 'mvn clean install'
                    sh 'mvn sonar:sonar -Dsonar.host.url=http://localhost:9000 -Dsonar.login=$sonartoken'
                }
            }
        }
        stage('Docker Build') {
            withCredentials([string(credentialsId: 'aws-repo', variable: 'awsRepo')]) {
                echo "Building and deploying docker image for $serviceName"
                docker.build('$serviceName:$commitHash')
                docker.withRegistry("https://$awsRepo", 'ecr:us-east-2:aws-credentials') {
                    docker.image('$serviceName:$commitHash').push("$commitHash")
                }
            }
        }
    }
}
