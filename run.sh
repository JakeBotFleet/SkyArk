#!/usr/bin/env bash
# SkyArk-Linux dispatcher
#
# Dispatches to the chosen SkyArk-Linux tool.
# AWS credentials are resolved entirely by boto3's standard credential chain
# (env vars → ~/.aws/credentials → IAM instance profile …).
#
# Usage:
#   ./run.sh stealth   [--region us-west-2 --output-dir ./out ...]
#   ./run.sh trace     download --bucket NAME --prefix PREFIX --local-path ./logs
#   ./run.sh trace     analyze  --local-path ./logs
#   ./run.sh recon     [--quick --output recon.json]
#
# See README.md → "AWS Credentials" for how to supply credentials.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# default region for the lab is us-west-2
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-west-2}"

cmd="${1:-}"; shift || true
case "${cmd}" in
  stealth)
    exec python3 "${SCRIPT_DIR}/AWStealth/awstealth.py" "$@"
    ;;
  trace)
    exec python3 "${SCRIPT_DIR}/AWStrace/awstrace.py" "$@"
    ;;
  recon)
    exec python3 "${SCRIPT_DIR}/AWSHostRecon/awshostrecon.py" "$@"
    ;;
  *)
    cat <<EOF
SkyArk-Linux dispatcher.
Usage: $(basename "$0") {stealth|trace|recon} [args...]

  stealth   IAM privileged-entity / Shadow Admin scan
  trace     CloudTrail download + analysis
  recon     Linux host recon for AWS artefacts

EOF
    exit 2
    ;;
esac
