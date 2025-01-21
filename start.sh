#!/bin/bash
export PORT="${PORT:-10000}"
hypercorn app:app --bind "0.0.0.0:$PORT" --access-logfile - --error-logfile -
