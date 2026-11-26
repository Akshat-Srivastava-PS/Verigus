#!/usr/bin/env bash
# One-line install for Verigus (working model).
#
#   curl -fsSL https://raw.githubusercontent.com/Akshat-Srivastava-PS/verigus/main/install.sh | bash
#
# ...or, from a local checkout:
#
#   ./install.sh
#
# What it does: installs dependencies (none beyond Node.js itself),
# generates the demo operator key, and starts the guard + demo shop.
# The guard comes up in OBSERVE mode by default — it learns the site
# before ever blocking anything.
set -euo pipefail

REPO_URL="https://github.com/Akshat-Srivastava-PS/verigus.git"
DIR="${VERIGUS_DIR:-$HOME/verigus}"

if [ ! -f package.json ]; then
  if [ -d "$DIR" ]; then
    cd "$DIR"
  else
    echo "Cloning the guard into $DIR ..."
    git clone "$REPO_URL" "$DIR"
    cd "$DIR"
  fi
fi

command -v node >/dev/null 2>&1 || { echo "Node.js 18+ is required: https://nodejs.org"; exit 1; }

echo "Installing dependencies (zero runtime dependencies)..."
npm install --no-audit --no-fund

echo ""
echo "Guard installed. Start it with:"
echo "  npm start"
echo ""
echo "Then open http://localhost:3000/dashboard (read-only) and run:"
echo "  npm run simulate"
echo ""
echo "The guard starts in OBSERVE mode and learns the site before enforcing."
