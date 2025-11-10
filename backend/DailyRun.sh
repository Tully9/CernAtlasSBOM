#!/bin/bash
# Daily SBOM Generation Script
# This script runs all project setup.sh scripts to generate SBOMs
# Designed to run daily via cron or scheduler

# Don't exit on error - we want to run all projects even if one fails
set +e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Log file for daily runs
LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/daily_run_$(date +%Y%m%d_%H%M%S).log"

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "=== Starting Daily SBOM Generation Run ==="

# Find all setup.sh files in project directories
PROJECTS_RUN=0
PROJECTS_SUCCESS=0
PROJECTS_FAILED=0
FAILED_PROJECTS=()

# Function to run a project's setup.sh
run_project_setup() {
    local project_name="$1"
    local project_dir="$SCRIPT_DIR/$project_name"
    local setup_script="$project_dir/setup.sh"
    
    if [ ! -d "$project_dir" ]; then
        log "Warning: Project directory $project_name does not exist"
        return 1
    fi
    
    if [ ! -f "$setup_script" ]; then
        log "Warning: setup.sh not found in $project_name"
        return 1
    fi
    
    log "Found project: $project_name"
    PROJECTS_RUN=$((PROJECTS_RUN + 1))
    
    # Change to project directory
    cd "$project_dir"
    
    log "Running setup.sh for $project_name..."
    
    # Run the setup script and capture output
    if bash setup.sh >> "$LOG_FILE" 2>&1; then
        log "✓ $project_name: SBOM generation completed successfully"
        PROJECTS_SUCCESS=$((PROJECTS_SUCCESS + 1))
        cd "$SCRIPT_DIR"
        return 0
    else
        log "✗ $project_name: SBOM generation failed"
        PROJECTS_FAILED=$((PROJECTS_FAILED + 1))
        FAILED_PROJECTS+=("$project_name")
        cd "$SCRIPT_DIR"
        return 1
    fi
}

# Run Athena and AnalysisBase first
log "Running priority projects first..."
run_project_setup "Athena"
run_project_setup "AnalysisBase"

# Look for setup.sh files in remaining subdirectories
for project_dir in */; do
    # Skip if not a directory
    if [ ! -d "$project_dir" ]; then
        continue
    fi
    
    PROJECT_NAME=$(basename "$project_dir")
    
    # Skip Athena and AnalysisBase since they were already run
    if [ "$PROJECT_NAME" = "Athena" ] || [ "$PROJECT_NAME" = "AnalysisBase" ]; then
        continue
    fi
    
    setup_script="$project_dir/setup.sh"
    
    # Check if setup.sh exists
    if [ -f "$setup_script" ]; then
        run_project_setup "$PROJECT_NAME"
    fi
done

# Summary
log "=== Daily Run Summary ==="
log "Projects found: $PROJECTS_RUN"
log "Projects succeeded: $PROJECTS_SUCCESS"
log "Projects failed: $PROJECTS_FAILED"

if [ ${#FAILED_PROJECTS[@]} -gt 0 ]; then
    log "Failed projects: ${FAILED_PROJECTS[*]}"
fi

log "=== Daily SBOM Generation Run Complete ==="

# Exit with error code if any projects failed
if [ $PROJECTS_FAILED -gt 0 ]; then
    exit 1
else
    exit 0
fi