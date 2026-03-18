#!/bin/zsh
# install-cloud-clis.zsh
# Installs: terraform, azure-cli, helm, kubectl on macOS (zsh)
set -euo pipefail

header() { printf "\n==== %s ====\n" "$1"; }

ensure_homebrew() {
  if ! command -v brew >/dev/null 2>&1; then
    header "Installing Homebrew"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

    # Add brew to zsh startup files (Apple Silicon path by default)
    if [ -x /opt/homebrew/bin/brew ]; then
      echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> "$HOME/.zprofile"
      echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> "$HOME/.zshrc"
      eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [ -x /usr/local/bin/brew ]; then
      # Intel Macs fallback
      echo 'eval "$(/usr/local/bin/brew shellenv)"' >> "$HOME/.zprofile"
      echo 'eval "$(/usr/local/bin/brew shellenv)"' >> "$HOME/.zshrc"
      eval "$(/usr/local/bin/brew shellenv)"
    fi
  else
    # Ensure brew env is active in current shell
    if [ -x /opt/homebrew/bin/brew ]; then
      eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [ -x /usr/local/bin/brew ]; then
      eval "$(/usr/local/bin/brew shellenv)"
    fi
  fi
  brew --version >/dev/null
}

install_tools() {
  header "Updating Homebrew"
  brew update

  header "Tapping HashiCorp (Terraform)"
  brew tap hashicorp/tap || true

  header "Installing Terraform, Azure CLI, Helm, kubectl"
  brew install hashicorp/tap/terraform azure-cli helm kubernetes-cli

  # Re-link if needed (harmless if already linked)
  brew link --overwrite terraform || true
  brew link --overwrite azure-cli || true
  brew link --overwrite helm || true
  brew link --overwrite kubernetes-cli || true
}

verify() {
  header "Verifying installations"
  printf "terraform: %s\n" "$(terraform version | head -n1 2>/dev/null || echo 'not found')"
  printf "az:        %s\n" "$(az version 2>/dev/null >/dev/null && az version | head -n1 || echo 'not found')"
  printf "helm:      %s\n" "$(helm version --short 2>/dev/null || echo 'not found')"
  printf "kubectl:   %s\n" "$(kubectl version --client --short 2>/dev/null || echo 'not found')"

  header "Done"
  echo "If a command is 'not found', open a new terminal or run: source ~/.zprofile && source ~/.zshrc"
}

main() {
  header "Starting setup (macOS + zsh)"
  ensure_homebrew
  install_tools
  verify
}

main "$@"

