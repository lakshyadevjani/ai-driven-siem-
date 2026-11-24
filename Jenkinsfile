pipeline {
    agent any

    options {
        disableConcurrentBuilds()
        timestamps()
    }

    environment {
        COMPOSE_PROJECT_NAME = 'ai-driven-siem-english'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Validate') {
            steps {
                sh 'cp .env.example .env'
                sh 'docker compose config --quiet'
            }
        }

        stage('Build') {
            steps {
                sh 'docker compose build siem'
            }
        }

        stage('Deploy') {
            when {
                expression { env.BRANCH_NAME == null || env.BRANCH_NAME == 'main' }
            }
            steps {
                withCredentials([
                    string(credentialsId: 'groq-api-key', variable: 'GROQ_API_KEY'),
                    string(credentialsId: 'flask-secret-key', variable: 'FLASK_SECRET_KEY')
                ]) {
                    sh '''
                        set +x
                        umask 077
                        printf 'GROQ_API_KEY=%s\\nFLASK_SECRET_KEY=%s\\n' \
                            "$GROQ_API_KEY" "$FLASK_SECRET_KEY" > .env
                        docker compose up -d
                    '''
                }
            }
        }
    }

    post {
        always {
            sh 'rm -f .env'
        }
    }
}
