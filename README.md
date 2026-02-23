# LoguardLLM

RAG-Powered Log Threat Detection System using Local LLMs on AMD GPUs.

## Overview

LoguardLLM is an intelligent security monitoring tool that leverages Large Language Models (LLMs) and Retrieval-Augmented Generation (RAG) to detect cybersecurity threats in web server logs. Unlike traditional rule-based systems, LoguardLLM uses semantic understanding to identify both known attack patterns and novel threats.

## Features

- **Two-Tier Embedding System**: Fast individual log embedding (mxbai) + rich context embedding (bge-m3)
- **Real-time Buffered Processing**: Immediate embedding with intelligent batch analysis
- **RAG-Based Analysis**: Multi-collection retrieval (individual logs + groups + summaries)
- **Intelligent Grouping**: Hardcoded grouping by status codes and IP/CIDR blocks for DDoS detection
- **Log Sentencification**: Human-readable key-value format for better embeddings
- **Static Asset Filtering**: Configurable exclusion of CSS/JS/images to focus on real threats
- **TTL-Based Cleanup**: Automatic deletion of old embeddings to prevent unbounded growth
- **Local LLM Inference**: Privacy-preserving analysis on AMD GPUs via Ollama
- **Continuous Monitoring**: Tail -f behavior with file watcher
- **Django Dashboard**: Web interface for viewing threats and configuration
- **Extensible Architecture**: Easy to add new log formats and LLM models

## Architecture

### Two-Tier Embedding System

```
Log File (continuous)
    ↓
File Watcher (tail -f)
    ↓
CLF Parser → Sentencify (key-value format)
    ↓                           ↓
Buffer (50 logs)        Fast Embedder (mxbai)
    ↓                           ↓
Intelligent Grouper     ChromaDB: individual_logs
    ↓
Group Summaries
    ↓
Context Embedder (bge-m3)
    ↓
ChromaDB: log_chunks
    ↓
RAG Retriever (30-60 min window)
    ↓
Threat Detector (LLM + RAG context)
    ↓
Analysis Summary → Context Embedder (bge-m3)
    ↓
ChromaDB: analysis_summaries
    ↓
SQLite DB → Django Dashboard
    ↑
TTL Cleanup Thread (auto-delete old embeddings)
```

## Prerequisites

- **Docker** and **Docker Compose**
- **AMD GPU** with ROCm support (e.g. RX 9070 XT) — or CPU-only (slower)
- At least **16GB RAM**
- **20GB** free disk space

## Local Setup

Follow these steps to run LoguardLLM on your machine.

### 1. Clone the repository

```bash
git clone git@github.com:codingsasi/loguard_llm.git loguard_llm
cd loguard_llm
```

Or if you already have the project:

```bash
cd /path/to/loguard_llm
```

### 2. Start services with Docker Compose

```bash
docker-compose up
```

This starts:

- **loguard_ollama** — Ollama with ROCm (AMD GPU support) for LLM and embeddings
- **loguard_app** — Django app (migrations, admin, dashboard, analyzer)

Check that both containers are running:

```bash
docker-compose ps
```

### 3. Pull required models (Ollama)

You need **one LLM** for threat analysis and **two embedding models** for the two-tier system:

```bash
# LLM for threat analysis (pick one; 7B is faster, 14B is more accurate)
docker exec -it loguard_ollama ollama pull qwen2.5:7b-instruct
# OR
docker exec -it loguard_ollama ollama pull qwen2.5:14b-instruct

# Embedding models (both required for real-time mode)
docker exec -it loguard_ollama ollama pull mxbai-embed-large   # Fast tier (individual logs)
docker exec -it loguard_ollama ollama pull bge-m3             # Context tier (groups/summaries)
```

Verify models:

```bash
docker exec loguard_ollama ollama list
```

### 4. Initialize Django

```bash
# Run migrations
docker exec loguard_app python manage.py migrate

# Create admin user (for dashboard and config)
docker exec -it loguard_app python manage.py createsuperuser
```

Follow the prompts to set username, email, and password.

### 5. (Optional) Apply recommended filters and reset state

To set smart filtering (excluded paths, status codes, methods) and clear old data:

```bash
docker exec loguard_app python reset_and_configure.py
```

### 6. Access the dashboard

- **Dashboard**: http://localhost:8000
- **Admin (config, threats)**: http://localhost:8000/admin

Log in with the superuser account you created.

### 7. Run the analyzer

**Real-time mode** (recommended):

```bash
docker exec -it loguard_app python manage.py run_analyzer --realtime
```

Log file path and other options are configured in Django admin under **Config** (see [Configuration](#configuration)).

### Summary: minimal local setup

```bash
cd loguard_llm
docker-compose up -d
docker exec loguard_ollama ollama pull qwen2.5:7b-instruct
docker exec loguard_ollama ollama pull mxbai-embed-large
docker exec loguard_ollama ollama pull bge-m3
docker exec loguard_app python manage.py migrate
docker exec -it loguard_app python manage.py createsuperuser
# Then open http://localhost:8000 and run_analyzer --realtime when ready
```

## Configuration

Edit the configuration via Django admin at **http://localhost:8000/admin/engine/config/**.

### Analysis Settings
- **Enabled**: Toggle analysis on/off
- **Analysis Interval**: How often to analyze logs (default: 30 seconds)
- **Max Logs Per Analysis**: Maximum logs to retrieve per analysis (default: 100)

### Log Source
- **Log File Path**: Path to Nginx access log (e.g. `/app/sample_logs/realtime.log` or `attack_simulation.log`)
- **Log Format**: CLF (Common Log Format) or Combined/Extended

### Filtering Options
- **Filter Static Assets**: Exclude CSS/JS/images (default: enabled)
- **Excluded Extensions**: File extensions to exclude (e.g. `.css,.js,.jpg,.png,.gif,.webp,.svg,.ico,.woff,.ttf,.map,.json,.xml,.mp4,.pdf`)
- **Excluded Paths**: Path substrings to exclude (legitimate app endpoints). Default: `/nodeviewcount,/analytics,/api/tracking,/api/metrics,/heartbeat,/health,/ping`. Requests whose path *contains* any of these are not analyzed.
- **Excluded User Agents**: Comma-separated substrings (case-insensitive). Default includes: `googlebot,bingbot,msnbot,slurp,duckduckbot,baiduspider,yandexbot,facebookexternalhit,twitterbot,linkedinbot,whatsapp,telegrambot`
- **Excluded Status Codes**: Comma-separated codes to exclude (e.g. `200,301,302,304` to focus on errors). Leave empty to include all.
- **Excluded Methods**: HTTP methods to exclude (e.g. `HEAD,OPTIONS`). Leave empty to include all.
- **Included Methods Override**: Methods to **always** include even if their status code is excluded (e.g. `POST,PUT,DELETE,PATCH`). Use this to still analyze POST 200 OK for spam/abuse while excluding normal GET 200 traffic.

### LLM Configuration
- **LLM Model**: Choose from:
  - `mistral:7b-instruct` (8K context) — fast, good for testing
  - `qwen2.5:7b-instruct` (32K context) — recommended balance
  - `llama3.1:8b` (128K context)
  - `qwen2.5:14b-instruct` (32K context) — more capable
  - `llama3.1:70b-instruct-q4_K_M` (128K context) — best quality, slower

### Embedding Models (Two-Tier System)
- **Fast Embedding Model**: `mxbai-embed-large` — embeds individual logs immediately
- **Context Embedding Model**: `bge-m3` — embeds groups and summaries

### Buffer & RAG Settings
- **Buffer Size**: Logs to accumulate before analysis (default: 50)
- **RAG Time Window**: Context retrieval window (default: 30 minutes)
- **VectorDB Retention**: TTL for embeddings; old data is auto-deleted (default: 60 minutes)

Intelligent grouping (4xx/5xx/IP/CIDR) is hardcoded for consistency.

## Usage

### Real-Time Mode (NEW - Recommended)

Continuous monitoring with two-tier embeddings:

```bash
docker exec -it loguard_app python manage.py run_analyzer --realtime
```

This will:
1. Watch log file continuously (tail -f behavior)
2. Sentencify each log to human-readable key-value format
3. Embed immediately with fast model (mxbai) → ChromaDB individual_logs
4. Buffer logs until 50 accumulated
5. Intelligently group by status codes (4xx/5xx) and IP/CIDR blocks
6. Generate group summaries, embed with context model (bge-m3) → ChromaDB log_chunks
7. Retrieve RAG context from last 30-60 minutes (individual + groups + summaries)
8. Analyze with LLM + RAG context
9. Embed analysis summary with context model → ChromaDB analysis_summaries
10. Store threats in database
11. Auto-cleanup old embeddings (TTL)

Press `Ctrl+C` to stop.

### Batch Mode (Legacy - Testing Only)

Process all logs in a file once:

```bash
docker exec -it loguard_app python manage.py run_analyzer --batch
```

Use this mode for quick testing on existing log files.

### View Results

#### Web Dashboard
Navigate to http://localhost:8000/ to see:
- Overview metrics (total threats, recent analysis runs)
- Threat alerts with details
- Analysis run history

#### Threat Details
Visit http://localhost:8000/threats/ to see detected threats with:
- Threat type (brute force, DDoS, SQL injection, path traversal, reconnaissance, bot activity)
- Severity level (critical, high, medium, low)
- Confidence score (0.0-1.0)
- Description and evidence (actual log entries)
- Actionable recommendations

## Development

### Project Structure

```
loguard_llm/
├── docker-compose.yml          # Container orchestration
├── Dockerfile                  # App container definition
├── requirements.txt            # Python dependencies
├── manage.py                   # Django management script
├── loguard/                    # Django project settings
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── engine/                     # Core analysis engine
│   ├── models.py              # Django models
│   ├── collector/             # Log collection
│   ├── indexer/               # RAG indexing
│   ├── llm/                   # LLM providers
│   └── analyzer/              # Threat detection
├── dashboard/                  # Web interface
│   ├── views.py
│   ├── urls.py
│   └── templates/
└── docs/                       # Documentation
    └── phase1_proposal.md
```

### Helper scripts

- **`reset_and_configure.py`** — Clears threats, analysis runs, and embeddings; applies recommended filters (excluded paths, status codes, methods). Run after changing config or to start fresh:
  ```bash
  docker exec loguard_app python reset_and_configure.py
  ```
- **`view_threats.py`** — Prints latest threat alerts and evidence from the database:
  ```bash
  docker exec loguard_app python view_threats.py
  ```
- **`configure_filters.py`** — Applies a predefined filter set (excluded status codes, method overrides) without clearing data.

## Supported Log Formats

- Common Log Format (CLF)
- NCSA Extended/Combined Log Format

## Threat Detection Categories

- **Brute Force**: Multiple failed authentication attempts
- **DDoS/DoS**: High request rates from single or distributed sources
- **SQL Injection**: Malicious SQL patterns in URLs
- **Path Traversal**: Directory traversal attempts
- **Reconnaissance**: Scanning and probing behavior
- **Bot Activity**: Suspicious automated traffic

## Performance

### With Intelligent Chunking + Static Filtering
- **Log Reduction**: 75-90% fewer logs to analyze (filters static assets)
- **Analysis Latency**: ~10-30 seconds per batch (50-100 logs)
- **Throughput**: 500-1000+ logs/minute
- **Token Efficiency**: 85-95% reduction vs. sending all logs to LLM
- **GPU Memory**:
  - Mistral 7B: ~4GB VRAM
  - Qwen 2.5 7B: ~5GB VRAM
  - Llama 3.1 70B (quantized): ~10-12GB VRAM

### Recommended Settings for Performance
- **Chunk Size**: 10-20 logs (smaller = faster embeddings)
- **Max Logs/Analysis**: 50-100 (balance between coverage and speed)
- **Model**: `qwen2.5:7b-instruct` for best speed/quality balance
- **Embedding**: `nomic-embed-text` for speed, `bge-m3` for larger context

## Troubleshooting

### Ollama not starting

Check GPU access:
```bash
ls -la /dev/kfd /dev/dri
```

Verify ROCm installation:
```bash
rocm-smi
```

### Embedding context length errors

If you see `the input length exceeds the context length`:
1. **Reduce chunk size**: Set to 5-10 logs in Django admin
2. **Use smaller log file**: Test with `attack_simulation.log` (1000 lines) instead of `access.log` (280k lines)
3. **Use larger embedding model**: Switch to `bge-m3` (8K context)

### ChromaDB errors

Clear the vector database and re-index:
```bash
docker exec loguard_app sh -c "rm -rf /app/chroma_data/*"
docker exec -it loguard_app python manage.py run_analyzer --batch
```

### Slow LLM inference

If analysis is taking too long:
1. **Use faster model**: Switch to `mistral:7b-instruct` or `qwen2.5:7b-instruct`
2. **Reduce max logs**: Set to 25-50 in Django admin
3. **Enable static filtering**: Reduces number of logs to analyze by 75%+

### Low detection accuracy

Try a larger model:
```bash
docker exec -it loguard_ollama ollama pull qwen2.5:14b-instruct
```

Update the model in Django admin and ensure intelligent chunking is enabled.

### No logs collected

Check log file path and permissions:
```bash
docker exec loguard_app ls -la /app/sample_logs/
```

Ensure the log file exists and is readable.

## License

MIT License (for educational purposes)

## Acknowledgments

- Drupalgeddon 2.0 case study for motivation
- Ollama team for local LLM runtime
- ChromaDB for vector database
- Django community

