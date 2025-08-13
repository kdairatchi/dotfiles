#!/bin/bash

# Ultimate Bug Bounty Framework Deployment Script
# Automated deployment with high-performance optimization

set -euo pipefail

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
readonly DEPLOYMENT_LOG="/tmp/deployment_$(date +%Y%m%d_%H%M%S).log"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$DEPLOYMENT_LOG"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$DEPLOYMENT_LOG"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$DEPLOYMENT_LOG"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$DEPLOYMENT_LOG"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$DEPLOYMENT_LOG"
}

# Banner
show_banner() {
    echo -e "${BLUE}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗           ║
║    ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝           ║
║    ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗             ║
║    ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝             ║
║    ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗           ║
║     ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝           ║
║                                                                              ║
║                DEPLOYMENT AUTOMATION SCRIPT                                  ║
║                High-Performance Bug Bounty Framework                         ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Usage
usage() {
    cat << 'EOF'
Ultimate Bug Bounty Framework Deployment Script

Usage: ./deploy.sh [options] <environment>

Environments:
  local       Deploy locally with Docker Compose
  production  Deploy to production environment
  cloud       Deploy to cloud infrastructure (AWS/GCP/Azure)
  k8s         Deploy to Kubernetes cluster

Options:
  -h, --help           Show this help message
  -v, --verbose        Enable verbose output
  -c, --config FILE    Use custom configuration file
  -s, --scale N        Scale to N scanner instances (default: 3)
  --no-build          Skip Docker image building
  --no-test           Skip deployment testing
  --cleanup           Clean up existing deployment first

Examples:
  ./deploy.sh local
  ./deploy.sh production --scale 5
  ./deploy.sh k8s --config k8s-config.yaml
  ./deploy.sh local --cleanup --verbose
EOF
}

# System checks
check_prerequisites() {
    log_info "Checking system prerequisites..."
    
    local required_tools=("docker" "docker-compose" "curl" "jq")
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Please install missing tools and try again"
        exit 1
    fi
    
    # Check Docker daemon
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    # Check available resources
    local available_memory=$(free -g | awk 'NR==2{print $7}')
    if [[ $available_memory -lt 4 ]]; then
        log_warning "Low available memory ($available_memory GB). Recommended: 8GB+"
    fi
    
    log_success "Prerequisites check completed"
}

# Environment-specific deployments
deploy_local() {
    log_info "Deploying to local environment with Docker Compose..."
    
    cd "$PROJECT_ROOT"
    
    # Build images if not skipping
    if [[ "${NO_BUILD:-false}" != "true" ]]; then
        log_info "Building Docker images..."
        docker-compose -f docker/docker-compose.yml build --parallel
    fi
    
    # Deploy services
    log_info "Starting services with ${SCALE:-3} scanner instances..."
    docker-compose -f docker/docker-compose.yml up -d --scale scanner-worker="${SCALE:-3}"
    
    # Wait for services to be ready
    log_info "Waiting for services to be ready..."
    sleep 30
    
    # Verify deployment
    if verify_deployment_local; then
        log_success "Local deployment completed successfully"
        show_local_endpoints
    else
        log_error "Local deployment verification failed"
        return 1
    fi
}

deploy_production() {
    log_info "Deploying to production environment..."
    
    # Load production configuration
    if [[ -f "${CONFIG_FILE:-deploy/production.env}" ]]; then
        source "${CONFIG_FILE:-deploy/production.env}"
        log_info "Loaded production configuration"
    else
        log_error "Production configuration file not found"
        exit 1
    fi
    
    # Production-specific optimizations
    export COMPOSE_FILE="docker/docker-compose.yml:docker/docker-compose.prod.yml"
    
    cd "$PROJECT_ROOT"
    
    # Build optimized images
    if [[ "${NO_BUILD:-false}" != "true" ]]; then
        log_info "Building production-optimized images..."
        docker-compose build --parallel
    fi
    
    # Deploy with production settings
    log_info "Deploying production services..."
    docker-compose up -d --scale scanner-worker="${SCALE:-5}"
    
    # Configure reverse proxy and SSL
    setup_production_proxy
    
    log_success "Production deployment completed"
}

deploy_kubernetes() {
    log_info "Deploying to Kubernetes cluster..."
    
    # Check kubectl
    if ! command -v kubectl >/dev/null 2>&1; then
        log_error "kubectl not found. Please install Kubernetes CLI tools"
        exit 1
    fi
    
    # Apply Kubernetes manifests
    log_info "Applying Kubernetes manifests..."
    kubectl apply -f k8s/namespace.yaml
    kubectl apply -f k8s/configmap.yaml
    kubectl apply -f k8s/secrets.yaml
    kubectl apply -f k8s/
    
    # Scale deployment
    kubectl scale deployment bug-bounty-scanner --replicas="${SCALE:-3}"
    
    # Wait for rollout
    kubectl rollout status deployment/bug-bounty-scanner
    
    log_success "Kubernetes deployment completed"
}

deploy_cloud() {
    log_info "Deploying to cloud infrastructure..."
    
    case "${CLOUD_PROVIDER:-aws}" in
        aws)
            deploy_aws
            ;;
        gcp)
            deploy_gcp
            ;;
        azure)
            deploy_azure
            ;;
        *)
            log_error "Unsupported cloud provider: ${CLOUD_PROVIDER}"
            exit 1
            ;;
    esac
}

# AWS deployment
deploy_aws() {
    log_info "Deploying to AWS using ECS/Fargate..."
    
    # Check AWS CLI
    if ! command -v aws >/dev/null 2>&1; then
        log_error "AWS CLI not found"
        exit 1
    fi
    
    # Deploy using AWS CDK or CloudFormation
    if [[ -f "aws/cdk/cdk.json" ]]; then
        cd aws/cdk
        npm install
        cdk deploy --require-approval never
    elif [[ -f "aws/cloudformation/template.yaml" ]]; then
        aws cloudformation deploy \
            --template-file aws/cloudformation/template.yaml \
            --stack-name bug-bounty-framework \
            --capabilities CAPABILITY_IAM
    else
        log_error "AWS deployment templates not found"
        exit 1
    fi
}

# Verification functions
verify_deployment_local() {
    log_info "Verifying local deployment..."
    
    # Check container status
    local running_containers=$(docker-compose -f docker/docker-compose.yml ps --services --filter "status=running" | wc -l)
    local expected_containers=6  # scanner, workers, db, redis, dashboard, api
    
    if [[ $running_containers -lt $expected_containers ]]; then
        log_error "Not all containers are running ($running_containers/$expected_containers)"
        docker-compose -f docker/docker-compose.yml ps
        return 1
    fi
    
    # Check API endpoint
    if ! curl -s http://localhost:3000/health >/dev/null; then
        log_error "API health check failed"
        return 1
    fi
    
    # Check dashboard
    if ! curl -s http://localhost:8080 >/dev/null; then
        log_error "Dashboard health check failed"
        return 1
    fi
    
    log_success "Deployment verification passed"
    return 0
}

# Show endpoints after successful deployment
show_local_endpoints() {
    log_info "Deployment completed successfully!"
    echo ""
    echo -e "${GREEN}Available Endpoints:${NC}"
    echo "  🌐 Dashboard:    http://localhost:8080"
    echo "  🔌 API:          http://localhost:3000"
    echo "  📊 Grafana:      http://localhost:3001 (admin/admin_change_me)"
    echo "  📈 Prometheus:   http://localhost:9090"
    echo "  🗄️  PostgreSQL:   localhost:5432 (scanner/secure_password_change_me)"
    echo "  📦 Redis:        localhost:6379"
    echo ""
    echo -e "${YELLOW}Quick Start Commands:${NC}"
    echo "  docker exec -it bug-bounty-scanner bash"
    echo "  docker exec -it bug-bounty-scanner quick_scan example.com"
    echo "  docker exec -it bug-bounty-scanner recon_pipeline example.com"
    echo ""
    echo -e "${BLUE}View Logs:${NC}"
    echo "  docker-compose -f docker/docker-compose.yml logs -f scanner"
    echo ""
    echo -e "${BLUE}Scale Workers:${NC}"
    echo "  docker-compose -f docker/docker-compose.yml up -d --scale scanner-worker=5"
}

# Cleanup function
cleanup_deployment() {
    log_info "Cleaning up existing deployment..."
    
    case "${ENVIRONMENT}" in
        local)
            docker-compose -f docker/docker-compose.yml down -v
            docker system prune -f
            ;;
        k8s)
            kubectl delete namespace bug-bounty-framework || true
            ;;
        production)
            docker-compose -f docker/docker-compose.yml -f docker/docker-compose.prod.yml down -v
            ;;
    esac
    
    log_success "Cleanup completed"
}

# Test deployment
test_deployment() {
    log_info "Running deployment tests..."
    
    # Run test scan
    local test_output=$(docker exec bug-bounty-scanner quick_sub_enum example.com 2>&1 || echo "FAILED")
    
    if [[ "$test_output" == *"FAILED"* ]]; then
        log_error "Test scan failed"
        return 1
    fi
    
    # Test parallel processing
    local parallel_jobs=$(docker exec bug-bounty-scanner bash -c 'source ~/.security_aliases && calc_parallel_jobs')
    
    if [[ $parallel_jobs -gt 100 ]]; then
        log_success "Parallel processing configured correctly ($parallel_jobs jobs)"
    else
        log_warning "Low parallel job count ($parallel_jobs)"
    fi
    
    log_success "Deployment tests passed"
}

# Main execution
main() {
    local environment=""
    local cleanup=false
    local verbose=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -s|--scale)
                SCALE="$2"
                shift 2
                ;;
            --no-build)
                NO_BUILD=true
                shift
                ;;
            --no-test)
                NO_TEST=true
                shift
                ;;
            --cleanup)
                cleanup=true
                shift
                ;;
            local|production|cloud|k8s)
                environment="$1"
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Validate environment
    if [[ -z "$environment" ]]; then
        log_error "Environment is required"
        usage
        exit 1
    fi
    
    # Enable verbose mode
    if [[ "$verbose" == true ]]; then
        set -x
    fi
    
    # Show banner
    show_banner
    
    # Export environment for other functions
    export ENVIRONMENT="$environment"
    
    log_info "Starting deployment to $environment environment"
    log_info "Deployment log: $DEPLOYMENT_LOG"
    
    # Check prerequisites
    check_prerequisites
    
    # Cleanup if requested
    if [[ "$cleanup" == true ]]; then
        cleanup_deployment
    fi
    
    # Deploy based on environment
    case "$environment" in
        local)
            deploy_local
            ;;
        production)
            deploy_production
            ;;
        cloud)
            deploy_cloud
            ;;
        k8s)
            deploy_kubernetes
            ;;
        *)
            log_error "Unsupported environment: $environment"
            exit 1
            ;;
    esac
    
    # Run tests unless skipped
    if [[ "${NO_TEST:-false}" != "true" ]]; then
        test_deployment
    fi
    
    log_success "Deployment completed successfully!"
    log_info "Full deployment log available at: $DEPLOYMENT_LOG"
}

# Error handling
trap 'log_error "Deployment failed at line $LINENO"; exit 1' ERR

# Execute main function
main "$@"