node {
    try {
        withEnv(['serviceName=boss-gateway']) {
            stage('Checkout') {
                echo "Checking out $serviceName"
                checkout scm
                sh 'git submodule update --init'
                // sh 'cd boss-core'
                // sh 'git checkout dev'
                // sh 'cd ..'
            }
            withEnv(["commitHash=${sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()}"]) {
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
                stage('Deploy') {
                    withCredentials([string(credentialsId: 'aws-account-id', variable: 'awsAccountId'), string(credentialsId: 'aws-repo', variable: 'awsRepo')]) {
                        echo 'Deploying cloudformation..'
                        sh "aws cloudformation deploy --stack-name $serviceName-stack --template-file ./ecs.yaml --parameter-overrides ApplicationName=$serviceName ApplicationEnvironment=dev ECRRepositoryUri=$awsRepo/$serviceName:$commitHash ExecutionRoleArn=arn:aws:iam::$awsAccountId:role/ecsTaskExecutionRole TargetGroupArn=arn:aws:elasticloadbalancing:us-east-2:$awsAccountId:targetgroup/default/a1d737973d78e824 --role-arn arn:aws:iam::$awsAccountId:role/awsCloudFormationRole --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM --region us-east-2"
                    }
                }
            }
        }
    }
    catch (exc) {
        echo "Caught: ${err}"
        currentBuild.result = 'FAILURE'
    } finally {
        stage('Cleanup') {
            sh 'mvn clean'
            sh "docker system prune -f"
        }
    }
}
