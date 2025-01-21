echo '#!/bin/bash
export PORT="${PORT:-10000}"
hypercorn app:app --bind "0.0.0.0:$PORT" --access-logfile - --error-logfile -' > start.sh

# Add and commit the files
git add start.sh render.yaml
git commit -m "Add start script and Render configuration"
git push
