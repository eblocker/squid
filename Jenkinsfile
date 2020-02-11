pipeline {
    agent any
    stages {
        stage('Build for Debian Jessie / ARM') {
            steps {
                sh "sudo docker run --rm -t -e BRANCH=${env.BRANCH_NAME} squidssl-arm:jessie"
            }
        }
        stage('Build for Debian Stretch / ARM') {
            steps {
                sh "sudo docker run --rm -t -e BRANCH=${env.BRANCH_NAME} squidssl-arm:stretch"
            }
        }
        stage('Build for Debian Stretch / AMD64') {
            steps {
                sh "sudo docker run --rm -t -e BRANCH=${env.BRANCH_NAME} squidssl-amd64:stretch"
            }
        }
    }
}
