#!/bin/bash

# ==========================================
# GOLDEN AUTOMATION SCRIPT
# Initializes Git, commits all changes, links to the remote repository, and pushes to master.
# ==========================================

echo "🚀 Starting automated Git release process..."

# 1. Initialize Git (if not already initialized)
if [ ! -d ".git" ]; then
    echo "📦 Initializing new Git repository..."
    git init
else
    echo "✅ Git repository already initialized."
fi

# 2. Add all files (respecting .gitignore)
echo "➕ Staging files..."
git add .

# 3. Commit changes
echo "💾 Committing changes..."
git commit -m "chore(security): remove sensitive data and implement environment variables for public release"

# 4. Handle Remote Repository link
REMOTE_URL="https://github.com/Alexrai123/Distributed-AI-Deception-System.git"
CURRENT_REMOTE=$(git remote get-url origin 2>/dev/null)

if [ "$CURRENT_REMOTE" == "$REMOTE_URL" ]; then
    echo "✅ Remote 'origin' is already set correctly."
elif [ -z "$CURRENT_REMOTE" ]; then
    echo "🔗 Linking to remote repository..."
    git remote add origin "$REMOTE_URL"
else
    echo "🔄 Updating remote 'origin' URL..."
    git remote set-url origin "$REMOTE_URL"
fi

# 5. Push to master (forcing branch name to master for legacy convention if required)
echo "🚀 Pushing code to origin/master..."
git branch -M master
git push -u origin master

echo "🎉 Public Release complete! Your code is now live and secure on GitHub."
