# Deploy the demo to a public URL (pick one)

All three serve the dashboard at `/` and the audit API under `/api/v1/a2a/`.
Set `OPENAI_API_KEY` to enable the "run live · real LLM" button.

## Fly.io (recommended — free tier, HTTPS URL)
```bash
fly launch --no-deploy --copy-config --name <your-app>   # uses deploy/fly.toml
fly secrets set OPENAI_API_KEY=sk-...                     # optional
fly deploy
# → https://<your-app>.fly.dev
```

## Railway (one click from the repo)
```bash
railway init
railway up                       # builds deploy/Dockerfile.demo (set root Dockerfile path)
railway variables set OPENAI_API_KEY=sk-...   # optional
# Railway assigns $PORT automatically; a2a_serve.py binds it.
```

## Docker anywhere (your own VPS / the lab server)
```bash
docker build -f deploy/Dockerfile.demo -t sentinel .
docker run -d -p 8099:8099 -e OPENAI_API_KEY=sk-... sentinel
# → http://<host>:8099
```

Then confirm: `curl https://<url>/healthz`.
