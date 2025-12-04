
pipeline {
    agent any
    
    environment {
        AWS_ACCESS_KEY_ID = credentials('aws-access-key-id')
        AWS_SECRET_ACCESS_KEY = credentials('aws-secret-access-key')
        DOCKER_REGISTRY = 'my-registry.company.com'
        IMAGE_NAME = 'aws-automation-tool'
    }
    
    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 30, unit: 'MINUTES')
    }
    
    stages {
        stage('代码检查') {
            steps {
                sh 'go vet ./...'
                sh 'go test ./... -v'
            }
        }
        
        stage('构建Docker镜像') {
            steps {
                script {
                    docker.build("${DOCKER_REGISTRY}/${IMAGE_NAME}:${env.BUILD_NUMBER}")
                }
            }
        }
        
        stage('安全扫描') {
            steps {
                sh 'trivy image --exit-code 0 --severity HIGH,CRITICAL ${DOCKER_REGISTRY}/${IMAGE_NAME}:${env.BUILD_NUMBER}'
            }
        }
        
        stage('推送镜像') {
            steps {
                script {
                    docker.withRegistry('https://${DOCKER_REGISTRY}', 'docker-credentials') {
                        docker.image("${DOCKER_REGISTRY}/${IMAGE_NAME}:${env.BUILD_NUMBER}").push()
                    }
                }
            }
        }
        
        stage('部署到生产') {
            when {
                branch 'main'
            }
            steps {
                sh '''
                    docker-compose down
                    docker-compose pull
                    docker-compose up -d
                '''
            }
        }
    }
    
    post {
        always {
            cleanWs()
        }
        success {
            slackSend(
                channel: '#infrastructure',
                message: "AWS自动化工具构建成功: ${env.BUILD_URL}"
            )
        }
        failure {
            slackSend(
                channel: '#infrastructure-alerts',
                message: "AWS自动化工具构建失败: ${env.BUILD_URL}"
            )
            emailext (
                subject: "AWS自动化工具构建失败 - ${env.JOB_NAME}",
                body: "构建 ${env.BUILD_URL} 失败",
                to: "infra-team@company.com"
            )
        }
    }
}
