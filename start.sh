#!/bin/bash
export PYTHONPATH=$PYTHONPATH:$(pwd)
uvicorn app:app --host 0.0.0.0 --port $PORT --workers 4 --log-level info
