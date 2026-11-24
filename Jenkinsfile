pipeline {
    agent any

    options {
        disableConcurrentBuilds()
        timestamps()
    }

    environment {
        COMPOSE_PROJECT_NAME = 'ai_siem'
        DATA_DIR = '/app/data'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Validate') {
            steps {
                sh 'python3 -m compileall -q app_groq.py db_create.py ollama_lib.py'
                sh 'docker compose config'
            }
        }

        stage('Build') {
            steps {
                sh 'docker compose build'
            }
        }

        stage('Deploy') {
            when {
                expression { env.BRANCH_NAME == null || env.BRANCH_NAME == 'main' || env.BRANCH_NAME == 'master' }
            }
            steps {
                sh 'docker compose up -d'
            }
        }
    }

    post {
        unsuccessful {
            sh 'docker compose ps || true'
        }
    }
}
