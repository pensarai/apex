#!/bin/bash
# durable-benchmark.sh - Run all XBEN benchmarks durably across multiple parallel processes
#
# Usage:
#   ./scripts/durable-benchmark.sh [options] [BENCHMARK_IDS...]
#
# Options:
#   -g, --groups NUM        Number of parallel groups (default: 4)
#   -p, --parallel NUM      Max parallel benchmarks per group (default: 10)
#   -c, --continue PREFIX   Continue from a previous run, only running missing benchmarks
#   -m, --model MODEL       Model ID to use (default: global.anthropic.claude-haiku-4-5-20251001-v1:0)
#   -h, --help              Show this help message
#
# Examples:
#   ./scripts/durable-benchmark.sh                          # Run all benchmarks
#   ./scripts/durable-benchmark.sh -g 2 -p 8                # Run with 2 groups, 8 parallel each
#   ./scripts/durable-benchmark.sh -c run-20251217-1317     # Continue from previous run
#   ./scripts/durable-benchmark.sh XBEN-001-24 XBEN-002-24  # Run specific benchmarks
#   ./scripts/durable-benchmark.sh -g 2 XBEN-001-24         # Run specific with options

set -e

# Default values
NUM_GROUPS=4
MAX_PARALLEL=10
CONTINUE_PREFIX=""
MODEL="global.anthropic.claude-haiku-4-5-20251001-v1:0"
BENCHMARK_IDS=()

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -g|--groups)
            NUM_GROUPS="$2"
            shift 2
            ;;
        -p|--parallel)
            MAX_PARALLEL="$2"
            shift 2
            ;;
        -c|--continue)
            CONTINUE_PREFIX="$2"
            shift 2
            ;;
        -m|--model)
            MODEL="$2"
            shift 2
            ;;
        -h|--help)
            head -20 "$0" | tail -19
            exit 0
            ;;
        -*)
            echo "Unknown option: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
        *)
            BENCHMARK_IDS+=("$1")
            shift
            ;;
    esac
done

# Array to track our background process PIDs
PIDS=()

# Kill only the specific processes we spawned (Ctrl+C, terminal close, etc.)
cleanup() {
    trap - SIGINT SIGTERM SIGHUP  # Prevent re-entry
    if [ ${#PIDS[@]} -gt 0 ]; then
        echo ""
        echo "Stopping benchmark processes..."
        for pid in "${PIDS[@]}"; do
            kill "$pid" 2>/dev/null || true
        done
        sleep 2
        for pid in "${PIDS[@]}"; do
            kill -9 "$pid" 2>/dev/null || true
        done
    fi
    exit 130
}
trap cleanup SIGINT SIGTERM SIGHUP

REPO="${XBEN_REPO:-$HOME/validation-benchmarks}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# If continuing from previous run, use same prefix; otherwise generate new one
if [ -n "$CONTINUE_PREFIX" ]; then
    PREFIX="$CONTINUE_PREFIX"
else
    PREFIX="run-$(date +%Y%m%d-%H%M)"
fi

LOG_DIR="$PROJECT_DIR/.benchmark-logs/$PREFIX"

# Increase Node.js memory limit (8GB per group process, system has 36GB)
export NODE_OPTIONS="--max-old-space-size=8192"

mkdir -p "$LOG_DIR"

# Verify repo exists
if [ ! -d "$REPO/benchmarks" ]; then
    echo "ERROR: Benchmarks directory not found at $REPO/benchmarks"
    echo "Set XBEN_REPO environment variable or edit this script"
    exit 1
fi

# Determine which benchmarks to run
BASELINE_COMPLETED=0
if [ ${#BENCHMARK_IDS[@]} -gt 0 ]; then
    # User supplied specific benchmark IDs
    ALL_BENCHMARKS=("${BENCHMARK_IDS[@]}")
elif [ -n "$CONTINUE_PREFIX" ]; then
    # Continue from previous run - find missing benchmarks
    echo "Checking previous run: $CONTINUE_PREFIX"

    # Get all available benchmarks
    AVAILABLE_BENCHMARKS=($(ls "$REPO/benchmarks" | grep "^XBEN" | sort))

    # Find which ones are missing results
    ALL_BENCHMARKS=()
    for b in "${AVAILABLE_BENCHMARKS[@]}"; do
        # Check if benchmark_results.json exists for this benchmark
        # Pattern: run-20251217-1317-g1-XBEN-007-24ses_xxx/benchmark_results.json
        if ! ls ~/.pensar/executions/${CONTINUE_PREFIX}-g*-${b}*/benchmark_results.json 2>/dev/null | head -1 | grep -q .; then
            ALL_BENCHMARKS+=("$b")
        fi
    done

    BASELINE_COMPLETED=$((${#AVAILABLE_BENCHMARKS[@]} - ${#ALL_BENCHMARKS[@]}))
    echo "Found $BASELINE_COMPLETED completed, ${#ALL_BENCHMARKS[@]} remaining"
    echo ""

    if [ ${#ALL_BENCHMARKS[@]} -eq 0 ]; then
        echo "All benchmarks already completed!"
        exit 0
    fi
else
    # Run all benchmarks
    ALL_BENCHMARKS=($(ls "$REPO/benchmarks" | grep "^XBEN" | sort))
fi

TOTAL=${#ALL_BENCHMARKS[@]}

if [ "$TOTAL" -eq 0 ]; then
    echo "ERROR: No benchmarks to run"
    exit 1
fi

# Adjust number of groups if we have fewer benchmarks than groups
if [ "$TOTAL" -lt "$NUM_GROUPS" ]; then
    NUM_GROUPS=$TOTAL
fi

echo "=============================================="
echo "DURABLE XBEN BENCHMARK RUNNER"
echo "=============================================="
echo "Repository:     $REPO"
echo "Model:          $MODEL"
echo "Groups:         $NUM_GROUPS"
echo "Parallel/group: $MAX_PARALLEL"
echo "Effective:      $((NUM_GROUPS * MAX_PARALLEL)) concurrent benchmarks"
echo "Prefix:         $PREFIX"
echo "Log dir:        $LOG_DIR"
echo "Benchmarks:     $TOTAL"
if [ -n "$CONTINUE_PREFIX" ]; then
    echo "Mode:           Continuing from previous run"
fi
echo "=============================================="
echo ""

# Calculate benchmarks per group
PER_GROUP=$(( (TOTAL + NUM_GROUPS - 1) / NUM_GROUPS ))

# Function to run a group with restart logic
run_group() {
    local group_num=$1
    shift
    local benchmarks=("$@")
    local group_prefix="${PREFIX}-g${group_num}"
    local log_file="$LOG_DIR/group-${group_num}.log"

    echo "[Group $group_num] Handling ${#benchmarks[@]} benchmarks" >> "$log_file"
    echo "[Group $group_num] Benchmarks: ${benchmarks[*]}" >> "$log_file"

    while true; do
        echo "" >> "$log_file"
        echo "[Group $group_num] Starting at $(date)" >> "$log_file"

        # Run the benchmark script (output only to log file)
        cd "$PROJECT_DIR"
        bun run scripts/daytona-benchmark.ts "$REPO" \
            --model "$MODEL" \
            --continue \
            --prefix "$group_prefix" \
            --max-parallel "$MAX_PARALLEL" \
            ${benchmarks[@]} >> "$log_file" 2>&1

        EXIT_CODE=$?

        if [ $EXIT_CODE -eq 0 ]; then
            echo "[Group $group_num] Completed successfully at $(date)" >> "$log_file"
            break
        fi

        # Check how many are actually remaining
        local remaining=0
        for b in "${benchmarks[@]}"; do
            if ! ls ~/.pensar/executions/${group_prefix}-${b}*/benchmark_results.json 2>/dev/null | head -1 | grep -q .; then
                ((remaining++)) || true
            fi
        done

        if [ $remaining -eq 0 ]; then
            echo "[Group $group_num] All benchmarks complete (exit was cleanup issue)" >> "$log_file"
            break
        fi

        echo "[Group $group_num] Exited with code $EXIT_CODE, $remaining benchmarks remaining" >> "$log_file"
        echo "[Group $group_num] Restarting in 15 seconds..." >> "$log_file"
        sleep 15
    done
}

# Split benchmarks into groups and launch
echo "Splitting $TOTAL benchmarks into $NUM_GROUPS groups..."
echo ""

for ((g=0; g<NUM_GROUPS; g++)); do
    start=$((g * PER_GROUP))
    end=$((start + PER_GROUP))
    if [ $end -gt $TOTAL ]; then
        end=$TOTAL
    fi

    # Extract slice of benchmarks for this group
    GROUP_BENCHMARKS=("${ALL_BENCHMARKS[@]:$start:$((end-start))}")

    if [ ${#GROUP_BENCHMARKS[@]} -eq 0 ]; then
        continue
    fi

    last_idx=$((${#GROUP_BENCHMARKS[@]} - 1))
    echo "Group $((g+1)): ${#GROUP_BENCHMARKS[@]} benchmarks (${GROUP_BENCHMARKS[0]} ... ${GROUP_BENCHMARKS[$last_idx]})"

    # Launch group in background
    run_group $((g+1)) "${GROUP_BENCHMARKS[@]}" &
    PIDS+=($!)
done

echo ""
echo "=============================================="
echo "Launched ${#PIDS[@]} groups in background"
echo "=============================================="
echo ""
echo "Logs: $LOG_DIR/"
echo "Kill: kill ${PIDS[*]}"
echo ""

# Progress bar function
draw_progress() {
    local completed=$1
    local total=$2
    local width=50
    local percent=$((completed * 100 / total))
    local filled=$((completed * width / total))
    local empty=$((width - filled))

    printf "\r["
    printf "%${filled}s" | tr ' ' '#'
    printf "%${empty}s" | tr ' ' '-'
    printf "] %d/%d (%d%%)" "$completed" "$total" "$percent"
}

# Check if any groups are still running
any_running() {
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

# Monitor progress with progress bar
echo "Running benchmarks..."
echo ""

while any_running; do
    RAW_COMPLETED=$(ls ~/.pensar/executions/${PREFIX}-g*-*/benchmark_results.json 2>/dev/null | wc -l | tr -d ' ')
    COMPLETED=$((RAW_COMPLETED - BASELINE_COMPLETED))
    draw_progress "$COMPLETED" "$TOTAL"
    sleep 2
done

# Final count
RAW_COMPLETED=$(ls ~/.pensar/executions/${PREFIX}-g*-*/benchmark_results.json 2>/dev/null | wc -l | tr -d ' ')
COMPLETED=$((RAW_COMPLETED - BASELINE_COMPLETED))
draw_progress "$COMPLETED" "$TOTAL"
echo ""

# Check for failures
FAILED=0
for pid in "${PIDS[@]}"; do
    if ! wait $pid 2>/dev/null; then
        ((FAILED++)) || true
    fi
done

echo ""
echo "=============================================="
echo "ALL GROUPS FINISHED"
echo "=============================================="

# Count results
RAW_COMPLETED=$(ls ~/.pensar/executions/${PREFIX}-g*-*/benchmark_results.json 2>/dev/null | wc -l | tr -d ' ')
COMPLETED=$((RAW_COMPLETED - BASELINE_COMPLETED))
echo "Completed: $COMPLETED / $TOTAL benchmarks"

if [ "$FAILED" -gt 0 ]; then
    echo "WARNING: $FAILED group(s) exited with errors"
fi

echo ""
echo "Results are in: ~/.pensar/executions/${PREFIX}-g*-*/"
echo "Logs are in: $LOG_DIR/"

# If not all completed, show how to continue
if [ "$COMPLETED" -lt "$TOTAL" ]; then
    echo ""
    echo "To continue this run later:"
    echo "  ./scripts/durable-benchmark.sh -c $PREFIX"
fi
