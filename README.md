# 🛡️ Wey Shield
**AI-powered security penetration testing — built in Ethiopia.**

Multilingual. Self-learning. Built to stand on its own two feet.

---

## Architecture

```
Client → POST /api/v1/scan
         │
         ├── AuthGate (ownership verification)
         ├── TitaniumAuthGate (scope lock — no drift during scan)
         │
         └── 5-Phase Pipeline:
               Phase 1: Universal Profiler  (nmap OS + service detection)
               Phase 2: Recon               (subfinder + httpx + nmap)
               Phase 3: Vuln Scan           (nuclei — adaptive template set)
               Phase 4: Patient Dragon      (stealth verification of critical findings)
               Phase 5: Micro-Chaos         (creeping stress test — finds breaking point)
               └──────► AI Interpreter      (Groq — multilingual report)
                         └──────────────► Training Archive (Supabase — the flywheel)
```

## Supported Languages
Amharic · Oromo · Tigrinya · English · Swahili · Somali · Arabic · French · Portuguese · Hausa

## Deployment

### 1. Supabase
Run `migrations/001_initial_schema.sql` in your Supabase SQL editor.

### 2. GitHub
```bash
git init
git add .
git commit -m "wey-shield v1.0"
git remote add origin https://github.com/YOUR_USERNAME/wey-shield
git push -u origin main
```

### 3. Render
- New Web Service → Connect GitHub → Select `wey-shield`
- Runtime: **Docker**, Dockerfile: `./docker/Dockerfile`
- Add environment variables from `.env.example`
- Deploy

### 4. UptimeRobot (keep Render warm on free tier)
- Monitor type: HTTP(s)
- URL: `https://wey-shield.onrender.com/health`
- Interval: 5 minutes

---

## API Reference

### Submit a scan
```bash
curl -X POST https://wey-shield.onrender.com/api/v1/scan \
  -H "x-client-id: tapu_foods" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["tapufoods.com"],
    "scan_type": "standard",
    "language": "am"
  }'
```

### Poll status
```bash
curl https://wey-shield.onrender.com/api/v1/scan/{job_id} \
  -H "x-client-id: tapu_foods"
```

### Get results
```bash
curl https://wey-shield.onrender.com/api/v1/scan/{job_id}/results \
  -H "x-client-id: tapu_foods"
```

### Submit feedback (trains the AI)
```bash
curl -X POST https://wey-shield.onrender.com/api/v1/scan/{job_id}/feedback \
  -H "x-client-id: tapu_foods" \
  -H "Content-Type: application/json" \
  -d '{"score": 5, "false_positives": [], "notes": "Very accurate report."}'
```

---

## The Self-Learning Flywheel

Every scan → Training Archive  
Every feedback → Quality label  
1,000 high-quality records → Fine-tune a small security LLM  
10,000 records → Wey Shield's own model, trained on African enterprise data  

Nobody else is building this corpus. That's the moat.

---

## Scan Types
| Type | Templates | Timeout | Use case |
|------|-----------|---------|----------|
| `quick` | Exposures + misconfigs | 2 min | Fast surface check |
| `standard` | + Vulns + SSL + DNS | 5 min | Default for most clients |
| `deep` | Full suite + CVEs | 10 min | Pre-launch audit |

---

*Built by Basliel Mihret — Wey AI Technologies — weyai.com.et*
