#!/bin/bash

# ============================================================================
# Chronix Installation Script
# Collaborative Pentesting Workspace
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
ORANGE='\033[38;5;208m'
NC='\033[0m'

# Banner
echo -e "${ORANGE}"
cat << 'EOF'
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     ██████╗██╗  ██╗██████╗  ██████╗ ███╗   ██╗██╗██╗  ██╗    ║
║    ██╔════╝██║  ██║██╔══██╗██╔═══██╗████╗  ██║██║╚██╗██╔╝    ║
║    ██║     ███████║██████╔╝██║   ██║██╔██╗ ██║██║ ╚███╔╝     ║
║    ██║     ██╔══██║██╔══██╗██║   ██║██║╚██╗██║██║ ██╔██╗     ║
║    ╚██████╗██║  ██║██║  ██║╚██████╔╝██║ ╚████║██║██╔╝ ██╗    ║
║     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝    ║
║                                                               ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

log_info() { echo -e "${CYAN}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$HOME/.config/chronix"
CONFIG_FILE="$CONFIG_DIR/chronix.env"

# ============================================================================
# Configuration Setup
# ============================================================================

setup_config() {
    log_info "Running Chronix initialization..."
    
    # Use chronix init to set up config and admin user
    # This is idempotent - safe to run if already initialized
    if command -v chronix &> /dev/null; then
        chronix init --db "$SCRIPT_DIR/chronix.db" 2>&1 || true
    else
        log_warn "chronix command not found yet - run 'chronix init' after installation"
    fi
}

# ============================================================================
# Installation Methods
# ============================================================================

install_pipx() {
    log_info "Installing Chronix via pipx..."
    
    # Check for pipx
    if ! command -v pipx &> /dev/null; then
        log_warn "pipx not found. Installing pipx first..."
        
        if command -v brew &> /dev/null; then
            brew install pipx
            pipx ensurepath
        elif command -v apt &> /dev/null; then
            sudo apt update && sudo apt install -y pipx
            pipx ensurepath
        elif command -v pip3 &> /dev/null; then
            pip3 install --user pipx
            python3 -m pipx ensurepath
        else
            log_error "Could not install pipx. Please install it manually:"
            echo "  https://pipx.pypa.io/stable/installation/"
            exit 1
        fi
        
        # Reload PATH
        export PATH="$HOME/.local/bin:$PATH"
    fi
    
    log_success "pipx available"
    
    # Install chronix from current directory
    log_info "Installing chronix package..."
    pipx install "$SCRIPT_DIR" --force
    
    # Reload PATH to ensure chronix is available
    export PATH="$HOME/.local/bin:$PATH"
    
    log_success "Chronix installed!"
    echo ""
    
    # Run chronix init to set up config and admin
    log_info "Initializing Chronix..."
    echo ""
    chronix init
    
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Installation Complete!${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${CYAN}Start Chronix:${NC}     chronix"
    echo -e "  ${CYAN}Custom port:${NC}       chronix --port 9000"
    echo -e "  ${CYAN}Local only:${NC}        chronix --local"
    echo ""
}

install_pip() {
    log_info "Installing Chronix via pip..."
    
    # Install in editable mode for development
    pip3 install -e "$SCRIPT_DIR"
    
    log_success "Chronix installed!"
    echo ""
    
    # Run chronix init
    log_info "Initializing Chronix..."
    echo ""
    chronix init
    
    echo ""
    echo -e "${GREEN}Run with:${NC} chronix"
    echo ""
}

install_dev() {
    log_info "Setting up development environment..."
    
    # Backend
    log_info "Installing Python dependencies..."
    pip3 install -e "$SCRIPT_DIR"
    
    # Frontend
    log_info "Installing Node.js dependencies..."
    cd "$SCRIPT_DIR/frontend"
    npm install
    
    # Run chronix init with debug mode
    log_info "Initializing Chronix for development..."
    echo ""
    CHRONIX_DEBUG=true chronix init
    
    # Enable debug mode in config if not already set
    CONFIG_FILE="$HOME/.config/chronix/chronix.env"
    if [ -f "$CONFIG_FILE" ] && ! grep -q "CHRONIX_DEBUG=true" "$CONFIG_FILE" 2>/dev/null; then
        echo "" >> "$CONFIG_FILE"
        echo "# Development mode" >> "$CONFIG_FILE"
        echo "CHRONIX_DEBUG=true" >> "$CONFIG_FILE"
    fi
    
    log_success "Development environment ready!"
    echo ""
    echo "To run in development mode:"
    echo "  Terminal 1: chronix --reload"
    echo "  Terminal 2: cd frontend && npm run dev"
    echo ""
}

uninstall() {
    log_info "Uninstalling Chronix..."
    
    if command -v pipx &> /dev/null; then
        pipx uninstall chronix 2>/dev/null || true
    fi
    pip3 uninstall chronix -y 2>/dev/null || true
    
    log_success "Chronix uninstalled"
    log_info "Configuration preserved at: $CONFIG_DIR"
    log_info "To fully remove: rm -rf $CONFIG_DIR"
}

show_help() {
    echo "Chronix Installation Script"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  install     Install via pipx (recommended)"
    echo "  pip         Install via pip (alternative)"
    echo "  dev         Setup development environment"
    echo "  uninstall   Remove Chronix"
    echo "  help        Show this help"
    echo ""
    echo "After installation:"
    echo "  chronix                    Start server"
    echo "  chronix init               Initialize (if not done during install)"
    echo "  chronix init --force       Regenerate session secret"
    echo "  chronix --local            Localhost only"
    echo "  chronix --port 9000        Custom port"
    echo ""
    echo "Configuration: ~/.config/chronix/chronix.env"
    echo ""
}

# ============================================================================
# Main
# ============================================================================

case "${1:-install}" in
    install)
        install_pipx
        ;;
    pip)
        install_pip
        ;;
    dev)
        install_dev
        ;;
    uninstall)
        uninstall
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
