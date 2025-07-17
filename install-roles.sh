#!/bin/bash

set -e

# Defaults
ROLES_DIR="Ansible/roles"
USER="$USER"
BASE_ROLE="bagelByt3s.ludushound"

print_help() {
  echo "Usage: $0 [install|remove] [-r DIR] [-u USER]"
  echo ""
  echo "Options:"
  echo "  install            Install all roles in the specified directory"
  echo "  remove             Remove all roles based on directory names"
  echo "  -r, --roles-dir    Path to the roles directory (default: Ansible/roles)"
  echo "  -u, --user         Ludus user (default: $USER)"
  echo "  -h, --help         Show this help message"
  echo ""
  echo "Example:"
  echo "  $0 install -r ./roles -u admin"
  exit 0
}

# Parse arguments
ACTION=""
ARGS=$(getopt -o r:u:h --long roles-dir:,user:,help -n "$0" -- "$@")
eval set -- "$ARGS"

while true; do
  case "$1" in
    -r|--roles-dir)
      ROLES_DIR="$2"
      shift 2
      ;;
    -u|--user)
      USER="$2"
      shift 2
      ;;
    -h|--help)
      print_help
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "Unknown option: $1"
      print_help
      ;;
  esac
done

# Remaining positional args
if [[ $# -lt 1 ]]; then
  echo "[!] Missing required action: install or remove"
  print_help
fi

ACTION="$1"

if [[ "$ACTION" != "install" && "$ACTION" != "remove" ]]; then
  echo "[!] Invalid action: $ACTION"
  print_help
fi

# Check roles directory exists
if [[ ! -d "$ROLES_DIR" ]]; then
  echo "[!] Roles directory not found: $ROLES_DIR"
  exit 1
fi

# Loop through each subfolder
for role_path in "$ROLES_DIR"/*/; do
  role_name=$(basename "$role_path")
  full_role="${BASE_ROLE}.${role_name}"

  case "$ACTION" in
    install)
      echo "[+] Installing role: $full_role"
      ludus --user "$USER" ansible role add -d "$role_path"
      ;;
    remove)
      echo "[-] Removing role: $full_role"
      ludus --user "$USER" ansible role remove "$role_name"
      ;;
  esac
done
