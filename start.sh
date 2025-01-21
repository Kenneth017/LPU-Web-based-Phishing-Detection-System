#!/bin/bash
export PYTHONPATH="${PYTHONPATH}:${PWD}"
hypercorn app:app --bind "0.0.0.0:$PORT" --access-logfile - --error-logfile - --workers 4
