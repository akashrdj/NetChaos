pipeline {
    agent any

    environment {
        COMPOSE_FILE = 'docker/docker-compose.yml'
        NETCHAOS_PROFILE = 'compliance-audit'
    }

    stages {
        stage('Build Topology Images') {
            steps {
                echo 'Building NetChaos isolated test network topology...'
                sh "docker-compose -f ${COMPOSE_FILE} build --no-cache"
            }
        }

        stage('Deploy Ephemeral Network') {
            steps {
                echo 'Starting virtual L2 bridge topology (Gateway, Victim, Test-Runner)...'
                sh "docker-compose -f ${COMPOSE_FILE} up -d"
                sh "sleep 5"
                echo 'Verifying network segment reachability...'
                sh "docker-compose -f ${COMPOSE_FILE} exec -T test-runner ping -c 3 172.20.0.2"
                sh "docker-compose -f ${COMPOSE_FILE} exec -T test-runner ping -c 3 172.20.0.3"
            }
        }

        stage('Dynamic Network Baseline Discovery') {
            steps {
                echo 'Profiling topology and learning authoritative gateway, DHCP, and OUI bindings...'
                sh "docker-compose -f ${COMPOSE_FILE} exec -T test-runner python netchaos.py profile --export /app/reports/baseline.json"
            }
        }

        stage('Execute NetChaos Security Battery') {
            steps {
                echo "Running curated security chaos battery: ${NETCHAOS_PROFILE}..."
                sh "docker-compose -f ${COMPOSE_FILE} exec -T test-runner python netchaos.py run --profile ${NETCHAOS_PROFILE} --active-defense"
            }
        }

        stage('CI/CD Gating & SLA Assertion') {
            steps {
                echo 'Asserting security SLAs (<5000ms latency, 100% attack detection)...'
                sh "docker-compose -f ${COMPOSE_FILE} exec -T test-runner python netchaos.py gate --profile ${NETCHAOS_PROFILE}"
            }
        }

        stage('Unit & Regression Test Suite') {
            steps {
                echo 'Running complete automated pytest validation suite...'
                sh "docker-compose -f ${COMPOSE_FILE} exec -T test-runner pytest -v"
            }
        }

        stage('Archive Audit & Telemetry Reports') {
            steps {
                echo 'Collecting SQLite compliance database and HTML execution reports...'
                sh """
                    docker cp \$(docker-compose -f ${COMPOSE_FILE} ps -q test-runner):/app/reports ./reports || true
                    docker cp \$(docker-compose -f ${COMPOSE_FILE} ps -q test-runner):/app/db/results.db ./reports/results.db || true
                """
                archiveArtifacts artifacts: 'reports/**', fingerprint: true, allowEmptyArchive: true
                publishHTML(target: [
                    allowMissing: true,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'reports',
                    reportFiles: 'report.html',
                    reportName: 'NetChaos Compliance & Security Report'
                ])
            }
        }
    }

    post {
        always {
            echo 'Tearing down ephemeral network topology...'
            sh "docker-compose -f ${COMPOSE_FILE} down -v"
        }
        success {
            echo '✅ [NETSECOPS GATE APPROVED] Network configuration passed all L2/L3 chaos drills. Safe to deploy.'
        }
        failure {
            echo '❌ [NETSECOPS GATE BLOCKED] Network security regression detected! Attack bypassed switch or breached SLA.'
        }
    }
}
