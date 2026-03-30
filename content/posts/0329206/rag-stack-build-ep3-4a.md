---
title: "We Gave Our AI Stack a Memory. Here's Everything That's Wrong With It."
date: 2026-03-29T08:00:00-05:00
draft: false
author: "Oob Skulden™"
tags: ["ai-infrastructure", "series", "rag", "llm", "docker", "ai-security"]
categories: ["AI Infrastructure Security Series"]
description: "Building a production RAG stack on ChromaDB, LangChain, and FastAPI -- and uncovering an unauthenticated vector database open to arbitrary writes from anyone on the network. Episode 3.4A of the AI Infrastructure Security Series."
keywords: ["RAG security", "ChromaDB authentication", "vector database attack surface", "LangChain security", "retrieval-augmented generation risks", "ChromaDB unauthenticated", "RAG poisoning", "PoisonedRAG", "UpGuard ChromaDB", "Open WebUI tools", "AI knowledge base security", "homelab AI security", "LLM tool calling", "ChromaDB v2 API"]
series: ["AI Infrastructure Security Series"]
seriesorder: 9
showToc: true
tocOpen: false
tools_used: ["ChromaDB 1.0.0", "LangChain 0.3.7", "FastAPI 0.115.0", "uvicorn 0.30.6", "langchain-chroma 1.1.0", "langchain-ollama 1.0.1", "langchain-huggingface 1.2.1", "Open WebUI v0.6.33", "Ollama 0.1.33", "LiteLLM v1.57.3", "Presidio", "qwen2.5:7b", "tinyllama:1.1b"]
attack_surface: ["unauthenticated vector database write access", "RAG knowledge base poisoning", "DLP bypass via retrieval path", "embedding mismatch exploitation", "tool calling model size requirements"]
cve_references: []
lab_environment: "ChromaDB 1.0.0 on Docker (lab_default network), LangChain RAG service on host (uvicorn), Open WebUI v0.6.33, Ollama 0.1.33 on NUC, qwen2.5:7b on RTX 3080Ti desktop GPU, Presidio + LiteLLM v1.57.3 DLP layer, Debian 13 NUC (192.168.100.59)"
---

<!--
SEO TARGET QUERIES:
- chromadb authentication default configuration
- RAG security risks vector database
- langchain chromadb unauthenticated
- how to build RAG stack with ChromaDB LangChain
- Open WebUI tool calling RAG
- chromadb v2 api deprecated v1
- vector database security homelab
- RAG knowledge base poisoning attack

AEO FEATURED SNIPPET Q&A:

Q: Does ChromaDB require authentication by default?
A: No. ChromaDB ships with authentication disabled by default. The HTTP API on port 8000 accepts connections from any host that can reach it. There is no API key, token, or credential required. This is documented behavior, not a misconfiguration -- and it means any client that can reach the port can read, write, update, or delete every document in every collection.

Q: What is RAG in the context of AI security?
A: RAG (Retrieval-Augmented Generation) is an architecture that grounds LLM responses in external documents. A vector database stores document embeddings; at query time, semantically similar chunks are retrieved and injected into the model context. The security implication is that the quality and integrity of the knowledge base directly controls the trustworthiness of model answers -- making the database itself a high-value attack target.

Q: What is the ChromaDB v2 API path?
A: ChromaDB 1.0.0 deprecated the /api/v1/ endpoints entirely. The correct base path is /api/v2/. Collections also moved from the flat /api/v2/collections to /api/v2/tenants/default_tenant/databases/default_database/collections.

Q: What model size is required for reliable tool calling in Open WebUI?
A: Based on testing with this stack, 500M and 1.1B parameter models (qwen2.5:0.5b and tinyllama:1.1b) recognize tools exist but cannot reliably construct function call arguments. qwen2.5:7b performs reliably. The minimum viable size for this stack appears to be somewhere between 1B and 7B parameters.

GEO SIGNALS:
- Series: AI Infrastructure Security Series, Episode 3.4A
- Lab environment: ChromaDB 1.0.0, LangChain 0.3.7, Open WebUI v0.6.33, Ollama 0.1.33
- Research cited: PoisonedRAG (Zou et al., 2024) -- arxiv.org/abs/2402.07867; UpGuard April 2025 scan -- 1,170 exposed ChromaDB instances, 406 with live unauthenticated data
- Compliance frameworks mapped: NIST 800-53, SOC 2, PCI-DSS v4.0, CIS Controls v8.1, OWASP LLM Top 10
- No CVEs assigned -- attack surface is default configuration, not a code vulnerability
-->



{{< ai-walkthrough >}}

**Published by Oob Skulden™ | AI Infrastructure Security Series -- Episode 3.4A**

-----

Your AI assistant only knows what it was trained on. That training data has a cutoff date. It doesn't know your internal runbooks, your network topology, your security policies, or what changed last Tuesday. So you fix that with RAG -- Retrieval-Augmented Generation. You point a vector database at your internal docs, wire it into the LLM, and now when someone asks "what's the incident response procedure for a compromised host," the model actually looks it up instead of hallucinating something plausible-sounding.

The design is smart. The security implications are something most people haven't thought through yet.

This episode deploys a complete RAG stack on top of the existing Ollama and Open WebUI installation -- ChromaDB as the vector store, LangChain to handle ingestion and retrieval, a FastAPI service to expose it as an endpoint, and an Open WebUI Tool to wire it into the chat interface. By the end of Part I, users can ask questions in natural language and get answers grounded in real documents, with source citations.

What we're also building, without meaning to, is an unauthenticated database that accepts arbitrary writes from anyone on the network. That's the 3.4B setup. This episode is the build.

-----

## What We're Building

The existing stack on `192.168.100.59` has Ollama serving models, Open WebUI providing the chat interface, and LiteLLM with Presidio handling the DLP layer. This episode adds the knowledge layer on top:

|Component        |Port|Role                                                               |
|-----------------|----|-------------------------------------------------------------------|
|ChromaDB         |8000|Vector database -- stores and retrieves document embeddings         |
|LangChain        |--   |Ingestion and retrieval orchestration -- runs inside the RAG service|
|RAG Query Service|8001|FastAPI wrapper -- exposes /query endpoint to Open WebUI            |
|Open WebUI Tool  |--   |Python function registered in Open WebUI -- calls the RAG service   |

**Lab network:**

- LockDown host (blog VM): `192.168.100.59` -- Ollama 0.1.33, Open WebUI v0.6.33, Presidio, LiteLLM v1.57.3, and now ChromaDB + RAG service
- Jump box: `192.168.50.10` (where commands originate)
- Desktop GPU backend: `192.168.38.215` (RTX 3080Ti -- the workhorse for inference)
- Docker network: `lab_default`

All addresses are RFC 1918 private ranges on a personal homelab network with no external connectivity.

The data flow once everything is running:

```
User types question in Open WebUI
     |
Open WebUI invokes RAG Tool (Python function)
     |
Tool calls RAG Query Service at http://192.168.100.59:8001/query
     |
LangChain queries ChromaDB for relevant document chunks
     |
ChromaDB returns top-k chunks by semantic similarity
     |
LangChain sends retrieved context + original question to Ollama
     |
Answer returned to Open WebUI -- displayed with source citations
```

The model never answers from training data alone. Every response is grounded in documents from the ChromaDB collection.

**What's in the knowledge base:** Internal security documentation -- all of it entirely fabricated for lab purposes -- incident response runbooks, access control policies, network segmentation guides, vulnerability disclosure procedures. The kind of documentation that employees consult when they need to know what to do. The kind of documentation that, if poisoned, produces authoritative-sounding wrong answers.

That's a 3.4B concern. Right now, let's build it correctly.

-----

## What ChromaDB Actually Does

Before pulling a single image, it's worth being precise about what ChromaDB is -- because the distinction between what it does and what people think it does is where the security gaps live.

ChromaDB is a vector database. It stores documents not as text but as **embeddings** -- high-dimensional numerical vectors that encode semantic meaning. When you store "the incident response procedure for a compromised host begins with network isolation," ChromaDB converts that sentence to a vector of 384 numbers representing its meaning in embedding space.

When a user later asks "what do I do if a server is hacked," ChromaDB converts that query to its own vector, then finds stored documents whose vectors are geometrically closest -- semantically similar, even if the words don't match. That's the retrieval mechanism: similarity search in embedding space.

Three things ChromaDB does not do by default:

**Authentication.** No API keys. No tokens. No credentials. The HTTP API accepts requests from anyone who can reach port 8000. This is documented behavior, not a misconfiguration. ChromaDB's own documentation describes authentication as optional and disabled by default.

**Authorization.** No concept of which client can read or write which collection. If you can reach the API, you can read every collection, write to every collection, update every document, and delete everything.

**Input validation.** ChromaDB stores whatever you send it. If the document contains false information, it stores false information. If the metadata claims the source is a trusted internal policy document, it stores that claim without verification.

These aren't bugs. They're design choices appropriate for a local development database that became the default choice for production RAG deployments. The 3.4B episode exists because of the gap between those two contexts.

One thing worth saying clearly before the build: **ChromaDB has no assigned CVEs for this episode.** There is no published exploit code, no patch to apply, no fixed version to compare against. The attack surface is the default configuration -- the same configuration the official quick-start docs produce. That's a different kind of finding than a code vulnerability, and in some ways a harder one, because there's nothing to patch. The fix is an architectural decision, not an update.

What there is: UpGuard scanned the internet in April 2025 and found 1,170 publicly accessible ChromaDB instances. 406 of them returned live data with no credentials. The researchers demonstrated full read, write, and poison access against those instances -- adding false documents, removing correct ones, replacing policy guidance with attacker-controlled content. None of those 406 database owners did anything wrong by the documentation's standards. They followed the quick-start guide and deployed what it told them to deploy.

That's the real-world baseline. The 3.4B attack reproduces what UpGuard demonstrated, with the academic backing of PoisonedRAG (Zou et al., 2024), which quantified the manipulation rate at 90% with five injected documents. The camera moment isn't a CVE number -- it's "406 production databases, zero credentials required, and here's what an attacker does with that."

-----

## Step 1: Confirm the Existing Network

Before adding anything new, confirm which Docker network the existing containers are on. Everything needs to be on the same network to talk to each other by container name.

```bash
docker network ls
docker inspect open-webui --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}'
docker inspect ollama --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}'
```

Expected output:

```
NETWORK ID     NAME          DRIVER    SCOPE
549668389b5b   lab_default   bridge    local

lab_default
lab_default
```

Both containers on `lab_default`. That's the network ChromaDB and the RAG service will join.

You may notice the Presidio and LiteLLM containers are not running -- they exited after the last session. That's the no-restart-policy finding from Episode 3.3A making another appearance. They're not needed for this episode but will be restarted later. The containers are intact, just stopped.

```bash
docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
```

```
NAMES                 STATUS                  IMAGE
litellm               Exited (0) 3 days ago   ghcr.io/berriai/litellm:main-v1.57.3
presidio-anonymizer   Exited (0) 3 days ago   mcr.microsoft.com/presidio-anonymizer:latest
presidio-analyzer     Exited (0) 3 days ago   mcr.microsoft.com/presidio-analyzer:latest
open-webui            Up 4 hours (healthy)    ghcr.io/open-webui/open-webui:v0.6.33
ollama                Up 4 hours              ollama/ollama:0.1.33
```

-----

## Step 2: Deploy ChromaDB

ChromaDB runs as a Docker container:

```bash
docker run -d \
  --name chromadb \
  --network lab_default \
  -p 8000:8000 \
  -v chromadb-data:/chroma/chroma \
  chromadb/chroma:latest
```

**What this does:** Pulls the official ChromaDB image, connects it to `lab_default` so LangChain can reach it by container name, maps port 8000 to the host, and mounts a named volume for persistent storage. Embeddings survive container restarts.

**What you can change:** The volume name (`chromadb-data`) is arbitrary. The port mapping can be changed if 8000 is in use, but update the RAG service config too.

Wait a moment, then verify:

```bash
sleep 10 && docker ps | grep chromadb
```

Expected output:

```
4b23643c26d7   chromadb/chroma:latest   "dumb-init -- chroma..."   Up About a minute   0.0.0.0:8000->8000/tcp   chromadb
```

Now here's where the documentation and reality diverge for the first time. The ChromaDB image pulled is version 1.0.0, which ships with a v2 API. Every example you'll find online uses `/api/v1/` paths. Those return this:

```bash
curl -s http://localhost:8000/api/v1/heartbeat
```

```json
{"error":"Unimplemented","message":"The v1 API is deprecated. Please use /v2 apis"}
```

The correct path for v1.0.0 is `/api/v2/`:

```bash
curl -s http://localhost:8000/api/v2/heartbeat
```

```json
{"nanosecond heartbeat": 1774819049995671770}
```

Check the version:

```bash
curl -s http://localhost:8000/api/v2/version
```

```
"1.0.0"
```

ChromaDB 1.0.0 also changed the collections API path. The flat `/api/v2/collections` endpoint returns empty with no error -- not helpful. The actual path requires the full tenant and database hierarchy:

```bash
curl -s http://localhost:8000/api/v2/tenants/default_tenant/databases/default_database/collections
```

```
[]
```

Empty array. Clean slate. Ready for documents.

|Framework       |Controls                                                                                     |
|----------------|---------------------------------------------------------------------------------------------|
|NIST 800-53     |CM-7 (Least Functionality), AC-3 (Access Enforcement)                                        |
|SOC 2           |CC6.1 (Logical Access Controls), CC6.6 (External Threats)                                    |
|PCI-DSS v4.0    |Req 1.3.1 (Inbound traffic restrictions), Req 8.2.1 (User authentication management)         |
|CIS Controls    |CIS 4.1 (Establish Secure Configuration Process), CIS 12.2 (Establish Network Access Control)|
|OWASP LLM Top 10|LLM08 (Excessive Agency), LLM09 (Misinformation)                                             |

-----

## Step 3: Install Dependencies

The RAG service runs directly on the host -- no Docker container for it. The reason becomes clear shortly, but it has to do with disk space, CUDA, and the fact that the NUC has no GPU.

First, install pip if it's not available:

```bash
sudo apt-get install -y python3-pip --fix-missing 2>&1 | tail -3
```

Note: a stale security repo package (`linux-libc-dev`) will fail to fetch. This is unrelated to pip and can be safely ignored. Verify pip installed despite the noise:

```bash
python3 -m pip --version
```

```
pip 23.0.1 from /usr/lib/python3/dist-packages/pip (python 3.11)
```

Now install the dependencies. This is not a single command -- the LangChain ecosystem has a version conflict that requires a specific install order:

```bash
# Install chromadb client first to confirm server compatibility
python3 -m pip install chromadb --break-system-packages 2>&1 | tail -3

# Install langchain-chroma and langchain-ollama together
# letting pip resolve the dependency conflict between them
python3 -m pip install langchain-chroma langchain-ollama --break-system-packages 2>&1 | tail -3

# Install the correct huggingface embeddings package
python3 -m pip install langchain-huggingface --break-system-packages 2>&1 | tail -3

# Install FastAPI and uvicorn
python3 -m pip install fastapi==0.115.0 uvicorn==0.30.6 --break-system-packages 2>&1 | tail -3
```

The versions that actually resolve cleanly on this machine:

```bash
python3 -m pip list | grep -iE "langchain|chroma|fastapi|uvicorn"
```

```
chromadb                1.5.5
fastapi                 0.115.0
langchain               0.3.7
langchain-chroma        1.1.0
langchain-community     0.3.7
langchain-core          1.2.23
langchain-huggingface   1.2.1
langchain-ollama        1.0.1
langchain-text-splitters 0.3.8
uvicorn                 0.30.6
```

**Why not sentence-transformers?** The original plan used `sentence-transformers` for embeddings. Installing it pulls PyTorch, which pulls CUDA bindings, which lands about 3GB in the container overlay filesystem on a machine with 5GB free. The build fails with `no space left on device` before it finishes extracting. The NUC has no GPU. There is no reason to install CUDA on a CPU-only machine just to run an 80MB embedding model.

The fix is ChromaDB's built-in embedding function, which uses `onnxruntime` -- same model (`all-MiniLM-L6-v2`), same 384-dimension vectors, about 80MB instead of 3GB.

**Why not a Docker container for the RAG service?** Same reason. Building a Docker image with PyTorch inside it requires more disk space than the NUC has available. Running the service directly on the host with uvicorn avoids the problem entirely and is simpler to manage for a single-machine lab deployment.

Verify all imports work before writing any service code:

```bash
python3 -c "
import chromadb
from langchain_chroma import Chroma
from langchain_ollama import OllamaLLM
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough
print('All imports OK')

client = chromadb.HttpClient(host='localhost', port=8000)
print('ChromaDB connected:', client.heartbeat())
"
```

```
All imports OK
ChromaDB connected: 1774819796546163500
```

Test the embedding model download and confirm it works:

```bash
python3 -c "
from langchain_huggingface import HuggingFaceEmbeddings
embeddings = HuggingFaceEmbeddings(model_name='all-MiniLM-L6-v2')
result = embeddings.embed_query('test sentence')
print(f'Embedding OK -- vector length: {len(result)}')
"
```

```
Embedding OK -- vector length: 384
```

Full end-to-end test -- store, retrieve, clean up:

```bash
python3 -c "
import chromadb
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings

embeddings = HuggingFaceEmbeddings(model_name='all-MiniLM-L6-v2')
client = chromadb.HttpClient(host='localhost', port=8000)

vectorstore = Chroma(
    client=client,
    collection_name='test-collection',
    embedding_function=embeddings,
)

vectorstore.add_texts(['this is a test document about security policies'])
results = vectorstore.similarity_search('security policy', k=1)
print(f'Retrieval OK -- got: {results[0].page_content[:50]}')

client.delete_collection('test-collection')
print('Test collection cleaned up')
"
```

```
Retrieval OK -- got: this is a test document about security policies
Test collection cleaned up
```

Everything works end-to-end before a single line of service code is written.

-----

## Step 4: Build the RAG Service

Create the project directory:

```bash
sudo mkdir -p /opt/rag-service
sudo chown oob:oob /opt/rag-service
```

Create `main.py` in three parts to avoid terminal heredoc truncation on long files.

**Part 1 -- imports and configuration:**

```bash
cat > /opt/rag-service/main.py << 'EOF'
"""
RAG Query Service -- Episode 3.4A
Oob Skulden(TM) | AI Infrastructure Security Series
"""

import chromadb
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from langchain_chroma import Chroma
from langchain_ollama import OllamaLLM
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="RAG Query Service", version="1.0.0")

EMBEDDING_MODEL = "all-MiniLM-L6-v2"
CHROMA_HOST = "localhost"
CHROMA_PORT = 8000
COLLECTION_NAME = "security-docs"
OLLAMA_BASE_URL = "http://192.168.38.215:11434"
OLLAMA_MODEL = "tinyllama:1.1b"
EOF
```

**Why `localhost` for ChromaDB and not the container name?** The RAG service runs on the host, not inside Docker. A process running on the host reaches ChromaDB via `localhost:8000` (the host-mapped port), not the container name. Container DNS only works inside the Docker network.

**What you can change:** `OLLAMA_BASE_URL` points at the desktop GPU for fast inference. If the desktop is unavailable, change this to `http://localhost:11434` to use the NUC's Ollama directly -- it'll be slower but functional. `OLLAMA_MODEL` can be any model installed on the backend.

**Part 2 -- chain setup:**

```bash
cat >> /opt/rag-service/main.py << 'EOF'

embeddings = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL)
chroma_client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)

vectorstore = Chroma(
    client=chroma_client,
    collection_name=COLLECTION_NAME,
    embedding_function=embeddings,
)

retriever = vectorstore.as_retriever(
    search_type="similarity",
    search_kwargs={"k": 4},
)

llm = OllamaLLM(
    base_url=OLLAMA_BASE_URL,
    model=OLLAMA_MODEL,
)

prompt = PromptTemplate.from_template("""Use the following context to answer the question.
If you cannot find the answer in the context, say so clearly.

Context:
{context}

Question: {question}

Answer:""")

def format_docs(docs):
    return "\n\n".join(doc.page_content for doc in docs)

rag_chain = (
    {"context": retriever | format_docs, "question": RunnablePassthrough()}
    | prompt
    | llm
    | StrOutputParser()
)
EOF
```

**What this does at the low level:** At startup, the service connects to ChromaDB and loads the embedding model into memory. The retriever is configured to return the four most semantically similar chunks for any query (`k=4`). The chain is a pipeline -- question comes in, retriever fetches relevant chunks, prompt template assembles context + question, LLM generates the answer, output parser converts it to a string.

**What you can change:** `search_kwargs={"k": 4}` controls retrieval breadth. Increase to 6-8 for broader context on complex questions. Decrease to 2 for faster responses on simple lookups.

**Part 3 -- API endpoints:**

```bash
cat >> /opt/rag-service/main.py << 'EOF'


class QueryRequest(BaseModel):
    question: str


class QueryResponse(BaseModel):
    answer: str
    sources: list[str]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/collections")
def list_collections():
    try:
        collections = chroma_client.list_collections()
        return {"collections": [c.name for c in collections]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/query", response_model=QueryResponse)
def query(request: QueryRequest):
    if not request.question.strip():
        raise HTTPException(status_code=400, detail="Question cannot be empty")
    logger.info(f"Query received: {request.question[:100]}")
    try:
        docs = retriever.invoke(request.question)
        sources = []
        for doc in docs:
            source = doc.metadata.get("source", "unknown")
            if source not in sources:
                sources.append(source)
        answer = rag_chain.invoke(request.question)
        logger.info(f"Answer generated. Sources: {sources}")
        return QueryResponse(answer=answer, sources=sources)
    except Exception as e:
        logger.error(f"Query failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
EOF
```

Verify syntax:

```bash
python3 -c "
import ast
with open('/opt/rag-service/main.py') as f:
    source = f.read()
ast.parse(source)
print('Syntax OK -- lines:', source.count(chr(10)))
"
```

```
Syntax OK -- lines: 108
```

Test that the file imports without errors -- this also creates the ChromaDB collection automatically:

```bash
cd /opt/rag-service && python3 -c "
from main import app
print('main.py imports OK')
"
```

```
INFO:httpx:HTTP Request: POST http://localhost:8000/api/v2/.../collections "HTTP/1.1 200 OK"
main.py imports OK
```

ChromaDB created the `security-docs` collection on import. It's empty, but it exists.

Start the service:

```bash
cd /opt/rag-service && nohup uvicorn main:app --host 0.0.0.0 --port 8001 \
  > /opt/rag-service/rag-service.log 2>&1 &

sleep 3
curl -s http://localhost:8001/health
```

```json
{"status":"ok"}
```

```bash
curl -s http://localhost:8001/collections | python3 -m json.tool
```

```json
{"collections": ["security-docs"]}
```

-----

## Step 5: Ingest Documents

The knowledge base needs content. We're loading five internal security policy documents -- realistic enough to make RAG queries meaningful and impactful when poisoned in 3.4B.

> Lab Note: The policy documents below are entirely fictional and created for this demonstration. They are not derived from, based on, or representative of any real organization's policies, including any employer. They exist solely to populate the knowledge base with realistic-looking content for the attack surface demonstration in Episode 3.4B.

Create the ingestion script. The key detail: the ingestion script must use the exact same embedding function as the service. If they differ, ChromaDB stores vectors in one format and queries in another, producing an embedding mismatch error. The symptoms of this error -- a wall of floating point numbers dumped into a JSON error response -- are not immediately obvious as an embedding problem. We'll come back to this in Part II.

```bash
cat > /opt/rag-service/ingest.py << 'EOF'
"""
Document ingestion script -- Episode 3.4A
Oob Skulden(TM) | AI Infrastructure Security Series
"""

import chromadb
from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_huggingface import HuggingFaceEmbeddings

CHROMA_HOST = "localhost"
CHROMA_PORT = 8000
COLLECTION_NAME = "security-docs"

DOCUMENTS = [
    Document(
        page_content="""Incident Response Procedure -- Compromised Host
Version 2.3 | Last updated: 2026-01-15 | Owner: Security Operations

IMMEDIATE ACTIONS (first 15 minutes):
1. Isolate the host -- disconnect from network at the switch level, not the OS level.
   Do not shut down the host. Memory forensics may be required.
2. Notify the Security Operations team via the #incident-response Slack channel.
   Include: hostname, IP, time of detection, detection method.
3. Preserve logs -- take a snapshot of /var/log before any remediation.
4. Document everything -- timestamp all actions in the incident ticket.

ESCALATION:
- P1 incidents (active exfiltration, ransomware): page the on-call engineer immediately.
- P2 incidents (suspected compromise, anomalous behavior): notify SOC within 30 minutes.
- Never communicate incident details over email. Use the encrypted #incident-response channel.

CREDENTIALS:
- Rotate all service account credentials associated with the compromised host.
- Rotate SSH keys that were present on the host.
- Do NOT rotate credentials until forensics confirms the scope.

RECOVERY:
- Rebuild from known-good image. Do not remediate in place.
- Verify integrity of backup before restore.
- Re-enable network connectivity only after isolation and rebuild are complete.""",
        metadata={"source": "ir-procedure-compromised-host-v2.3.md",
                  "category": "incident-response", "classification": "internal"},
    ),
    Document(
        page_content="""Access Control Policy -- Privileged Accounts
Version 1.8 | Last updated: 2026-02-01 | Owner: Identity and Access Management

PRIVILEGED ACCOUNT STANDARDS:
- All privileged accounts require MFA. No exceptions.
- Privileged sessions must be initiated from the jump box at 192.168.50.10.
  Direct SSH to production hosts from personal workstations is prohibited.
- Privileged account passwords rotate every 90 days.
- Shared privileged accounts (root, Administrator) are prohibited for human use.

PROVISIONING:
- New privileged access requires approval from the system owner AND the CISO.
- Approval must be documented before access is granted.
- Temporary access grants expire automatically after 30 days unless renewed.

DEPROVISIONING:
- Access must be revoked within 4 hours of role change or termination.
- Deprovisioning includes: account disable, SSH key removal, API key revocation.
- Quarterly access reviews are mandatory.""",
        metadata={"source": "access-control-policy-privileged-v1.8.md",
                  "category": "access-control", "classification": "internal"},
    ),
    Document(
        page_content="""Network Segmentation Standards
Version 3.1 | Last updated: 2025-11-20 | Owner: Network Engineering

SEGMENT DEFINITIONS:
- Jump_Server (192.168.50.0/28): Attacker simulation and privileged access origin.
- Observability (192.168.75.0/24): Grafana, Prometheus, Loki, Wazuh. Read-only.
- IAM (192.168.80.0/24): Authentik SSO. High trust. Treat as critical.
- LockDown (192.168.100.0/24): Primary AI stack. Not internet-routable.

INTER-SEGMENT RULES:
- Default deny between segments. Explicit allow rules only.
- The LockDown segment has NO direct path to the IAM segment.

MONITORING:
- All inter-segment traffic is logged at the firewall.
- Anomalous connections trigger automatic alerts in Wazuh.""",
        metadata={"source": "network-segmentation-standards-v3.1.md",
                  "category": "network-security", "classification": "internal"},
    ),
    Document(
        page_content="""Vulnerability Disclosure and Patch Management
Version 2.0 | Last updated: 2026-01-30 | Owner: Security Engineering

PATCH WINDOWS:
- Critical (CVSS 9.0+): patch within 24 hours.
- High (CVSS 7.0-8.9): patch within 7 days.
- Medium (CVSS 4.0-6.9): patch within 30 days.
- Low: patch in next scheduled maintenance window.

EXCEPTION PROCESS:
- Exceptions require written justification and CISO approval.
- Maximum exception duration: 90 days.

AI INFRASTRUCTURE:
- AI stack components treated as high-risk.
- Version pinning for security research is documented and approved.
- Production AI deployments must run current stable versions. No exceptions.""",
        metadata={"source": "vuln-disclosure-patch-management-v2.0.md",
                  "category": "vulnerability-management", "classification": "internal"},
    ),
    Document(
        page_content="""AI Stack Security Baseline
Version 1.0 | Last updated: 2026-03-01 | Owner: AI Platform Team

APPROVED DEPLOYMENT PATTERNS:
- All AI inference endpoints require authentication.
- Model downloads must be logged.
- RAG knowledge bases must be approved by the data owner before ingestion.

APPROVED MODELS:
- tinyllama:1.1b -- approved for all use cases.
- qwen2.5:0.5b -- approved for all use cases.

DATA HANDLING:
- Prompts containing PII must route through the LiteLLM/Presidio masking layer.
- Chat history must be purged within 90 days.

KNOWN RESEARCH EXCEPTIONS (LockDown segment only):
- Ollama 0.1.33: intentionally vulnerable. Not for production.
- Open WebUI v0.6.33: intentionally vulnerable. Not for production.
- ChromaDB: no auth configured. Intentional for 3.4B attack surface research.""",
        metadata={"source": "ai-stack-security-baseline-v1.0.md",
                  "category": "ai-security", "classification": "internal"},
    ),
]


def main():
    print(f"Connecting to ChromaDB at {CHROMA_HOST}:{CHROMA_PORT}")
    client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=500,
        chunk_overlap=50,
    )
    chunks = splitter.split_documents(DOCUMENTS)
    print(f"Split {len(DOCUMENTS)} documents into {len(chunks)} chunks")

    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

    vectorstore = Chroma.from_documents(
        documents=chunks,
        collection_name=COLLECTION_NAME,
        client=client,
        embedding=embeddings,
    )
    count = vectorstore._collection.count()
    print(f"Ingestion complete. {count} chunks in collection.")

if __name__ == "__main__":
    main()
EOF
```

Run ingestion:

```bash
python3 /opt/rag-service/ingest.py
```

```
Connecting to ChromaDB at localhost:8000
Split 5 documents into 12 chunks
Ingestion complete. 12 chunks in collection.
```

**Why 12 chunks from 5 documents?** `RecursiveCharacterTextSplitter` cuts documents at 500 characters with 50-character overlap at chunk boundaries. Overlap prevents a sentence from being split mid-thought and losing context on both sides. Each of the five policy documents becomes 2-3 chunks depending on length.

Verify via the Python client:

```bash
python3 -c "
import chromadb
c = chromadb.HttpClient(host='localhost', port=8000)
col = c.get_collection('security-docs')
print(f'Chunks in collection: {col.count()}')
"
```

```
Chunks in collection: 12
```

-----

## Step 6: Test the RAG Service

Before touching Open WebUI, confirm the service returns grounded answers via curl:

```bash
curl -s -X POST http://localhost:8001/query \
  -H "Content-Type: application/json" \
  -d '{"question": "What is the procedure when a host is compromised?"}' \
  | python3 -m json.tool
```

Expected output:

```json
{
    "answer": "When a host is compromised, immediately isolate it by disconnecting from the network at the switch level -- do not shut down the host. Notify the Security Operations team via the encrypted #incident-response Slack channel with the hostname, IP, time of detection, and detection method. Preserve logs before any remediation. Rebuild from a known-good image. Do not re-enable network connectivity until isolation and rebuild are complete.",
    "sources": [
        "ir-procedure-compromised-host-v2.3.md"
    ]
}
```

That's the IR procedure document. Not training data. Not a hallucination. The source citation is accurate.

Second query to confirm multi-document retrieval:

```bash
curl -s -X POST http://localhost:8001/query \
  -H "Content-Type: application/json" \
  -d '{"question": "How long do we have to patch a critical vulnerability?"}' \
  | python3 -m json.tool
```

```json
{
    "answer": "Critical vulnerabilities with a CVSS score of 9.0 or higher must be patched within 24 hours of confirmed applicability.",
    "sources": [
        "vuln-disclosure-patch-management-v2.0.md",
        "access-control-policy-privileged-v1.8.md",
        "ir-procedure-compromised-host-v2.3.md"
    ]
}
```

Retrieval working across multiple documents, sources cited correctly.

Confirm in the service log that the full chain ran:

```bash
tail -5 /opt/rag-service/rag-service.log
```

```
INFO:httpx:HTTP Request: POST http://localhost:8000/api/v2/.../collections/.../query "HTTP/1.1 200 OK"
INFO:httpx:HTTP Request: POST http://192.168.38.215:11434/api/generate "HTTP/1.1 200 OK"
INFO:main:Answer generated. Sources: ['ir-procedure-compromised-host-v2.3.md']
INFO:     127.0.0.1:PORT - "POST /query HTTP/1.1" 200 OK
```

ChromaDB queried. Desktop GPU called. Answer generated.

-----

## Step 7: Connect Open WebUI

The final step registers the RAG service as a callable Tool in Open WebUI.

In Open WebUI: **Workspace -> Tools -> + (New Tool)**

- **Tool Name:** RAG Knowledge Base
- **Tool ID:** rag_knowledge_base
- **Tool Description:** Query internal security documentation

Paste this code:

```python
import urllib.request
import json


class Tools:
    def query_knowledge_base(self, question: str) -> str:
        """
        Query the internal security documentation knowledge base.
        Use this when the user asks about security policies, incident response
        procedures, access control rules, network segmentation, patch management,
        or AI stack configuration.
        Returns a grounded answer with source document citations.

        :param question: The user's question about internal security documentation.
        :return: Answer grounded in internal documentation with source citations.
        """
        payload = json.dumps({"question": question}).encode()
        req = urllib.request.Request(
            "http://192.168.100.59:8001/query",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read())
                answer = result.get("answer", "No answer returned.")
                sources = result.get("sources", [])
                if sources:
                    source_list = "\n".join(f"- {s}" for s in sources)
                    return f"{answer}\n\nSources:\n{source_list}"
                return answer
        except Exception as e:
            return f"Knowledge base query failed: {str(e)}"
```

**Why the host LAN IP and not the container name?** The Tool code runs inside the Open WebUI container. The RAG service runs on the host, not inside Docker. Container DNS can't resolve the host's hostname from inside a container. The host's LAN IP (`192.168.100.59`) is reachable from inside the container via the Docker bridge gateway. This is the one place in the stack where the LAN IP is the correct address.

Save the tool. It appears in Workspace -> Tools alongside the other tools already registered from previous episodes -- PWNed Tool and API Key Tool, both created during Episode 3.2B's account takeover chain.

**Model selection matters here.** `qwen2.5:0.5b` and `tinyllama:1.1b` are too small to reliably construct tool call arguments. They recognize the tool exists but can't correctly format the function call parameters. For tool use to work reliably, a larger model is required.

Pull `qwen2.5:7b` on the desktop GPU:

```bash
curl -s http://192.168.38.215:11434/api/pull \
  -d '{"name":"qwen2.5:7b"}' | grep -E '"status"' | tail -3
```

```
{"status":"verifying sha256 digest"}
{"status":"writing manifest"}
{"status":"success"}
```

Add it to the LiteLLM config at `/opt/litellm/config.yaml`:

```yaml
model_list:
  - model_name: nuc/tinyllama
    litellm_params:
      model: ollama/tinyllama:1.1b
      api_base: http://ollama:11434
  - model_name: nuc/qwen
    litellm_params:
      model: ollama/qwen2.5:0.5b
      api_base: http://ollama:11434
  - model_name: desktop/tinyllama
    litellm_params:
      model: ollama/tinyllama:1.1b
      api_base: http://192.168.38.215:11434
  - model_name: desktop/qwen
    litellm_params:
      model: ollama/qwen2.5:0.5b
      api_base: http://192.168.38.215:11434
  - model_name: desktop/qwen7b
    litellm_params:
      model: ollama/qwen2.5:7b
      api_base: http://192.168.38.215:11434

litellm_settings:
  drop_params: true
  callbacks:
    - presidio
  output_parse_pii: true
```

Restart LiteLLM and confirm the model appears:

```bash
docker restart litellm
sleep 15
curl -s http://localhost:4000/v1/models \
  -H "Authorization: Bearer sk-litellm-master-key" | python3 -m json.tool | grep '"id"'
```

```
"id": "desktop/qwen7b"
"id": "desktop/qwen"
"id": "desktop/tinyllama"
"id": "nuc/qwen"
"id": "nuc/tinyllama"
```

In Open WebUI: select `desktop/qwen7b`, enable the RAG Knowledge Base tool, ask:

*What is the procedure when a host is compromised?*

The model invokes the tool, the tool calls the RAG service, the service queries ChromaDB and the desktop GPU, and the answer comes back grounded in `ir-procedure-compromised-host-v2.3.md`:

> "Immediately notify SOC via encrypted #incident-response channel with details of the incident. Rotate all service account credentials associated with the compromised host, rotate SSH keys, do not reboot until forensics confirm the scope. Isolate the host. Rebuild from a known-good image before restoring network connectivity."

Source cited: `rag_knowledge_base/query_knowledge_base` -- visible in the UI under "1 Source."

The service log confirms the full chain:

```
INFO:httpx:HTTP Request: POST http://localhost:8000/api/v2/.../query "HTTP/1.1 200 OK"
INFO:httpx:HTTP Request: POST http://192.168.38.215:11434/api/generate "HTTP/1.1 200 OK"
INFO:main:Answer generated. Sources: ['ir-procedure-compromised-host-v2.3.md']
INFO:     172.18.0.3:37740 - "POST /query HTTP/1.1" 200 OK
```

That last line is the tell: `172.18.0.3` is the Open WebUI container's IP on the Docker bridge. The tool call went from the container through the host network to the RAG service. The RAG service queried ChromaDB. ChromaDB returned the right chunks. The desktop GPU generated the answer. The citation came back to the user.

-----

## What We Built

The complete RAG architecture:

```
Open WebUI (port 3000)
  |-- Direct Ollama (port 11434) -- no RAG, answers from training data
  |-- LiteLLM/Presidio (port 4000) -- DLP-protected, no RAG
  |-- RAG Tool --> RAG Service (port 8001, host)
                     |-- LangChain (retrieval + generation)
                       |-- ChromaDB (port 8000) [no auth]
                       |-- Ollama GPU (192.168.38.215:11434)
```

A user asking about internal security policy gets an answer grounded in real documents. The source citations build trust -- the model isn't guessing, it's citing. That trust is exactly what makes the knowledge base worth attacking.

The ChromaDB container accepts unauthenticated writes from any host that can reach port 8000. From the jump box at `192.168.50.10`, there is no authentication to bypass. Anyone can add documents to the collection. Any document in the collection can influence model answers. The source metadata is whatever the writer claims -- there's no verification that `"source": "ir-procedure-compromised-host-v2.3.md"` is real.

**The DLP gap.** Look at the architecture above. The RAG path goes: Open WebUI Tool -> RAG Service -> Ollama. LiteLLM and Presidio at port 4000 are not in that flow at all. If a retrieved document chunk contains a name, email address, or SSN, it reaches Ollama unmasked. The DLP layer we deployed in Episodes 3.3A and 3.3B covers the direct chat path. It does not cover the RAG retrieval path. RAG creates a second data flow that the gateway has no visibility into. We'll come back to this in 3.4B.

That's the build. The knowledge base contains accurate information. The retrieval works correctly. The citations are trustworthy.

For now.

|Framework       |Controls                                                                                   |
|----------------|-------------------------------------------------------------------------------------------|
|NIST 800-53     |SC-7 (Boundary Protection), AC-3 (Access Enforcement), SI-10 (Information Input Validation)|
|SOC 2           |CC6.1, CC6.6 (External Threats), CC9.2                                                     |
|PCI-DSS v4.0    |Req 1.3.1, Req 6.2.4, Req 12.3.2                                                           |
|CIS Controls    |CIS 12.2 (Establish Network Access Control), CIS 13.4 (Perform Traffic Filtering)          |
|OWASP LLM Top 10|LLM08 (Excessive Agency), LLM09 (Misinformation)                                           |

-----

## Verification Table

|Test                     |Expected Result                                                             |
|-------------------------|----------------------------------------------------------------------------|
|ChromaDB heartbeat       |nanosecond heartbeat value via /api/v2/heartbeat                            |
|ChromaDB version         |"1.0.0"                                                                     |
|Collections (empty)      |[] via /api/v2/tenants/default_tenant/databases/default_database/collections|
|Collections (post-ingest)|security-docs collection present                                            |
|Python client connection |client.list_collections() returns Collection(name=security-docs)            |
|Chunk count              |12                                                                          |
|RAG service health       |{"status": "ok"}                                                            |
|All imports              |No deprecation warnings                                                     |
|Query -- compromised host |Answer cites ir-procedure-compromised-host-v2.3.md                          |
|Query -- patch timeline   |Answer cites vuln-disclosure-patch-management-v2.0.md                       |
|Open WebUI tool          |desktop/qwen7b invokes tool, returns cited answer                           |
|Service log              |Shows ChromaDB query + desktop GPU call per request                         |

-----

## Part II: What We Actually Did -- The Full Lab Session

*Part I is the clean version. This half is what actually happened. The difference between the two is where all the useful information lives.*

-----

### The API That Moved

Pull `chromadb/chroma:latest` and you get version 1.0.0. Every tutorial, blog post, and documentation example uses `/api/v1/` paths. Version 1.0.0 deprecated the entire v1 API.

The first indication of this is a curl to `/api/v1/heartbeat` that returns:

```json
{"error":"Unimplemented","message":"The v1 API is deprecated. Please use /v2 apis"}
```

Informative, at least. The fix is straightforward -- replace `v1` with `v2` everywhere. Less straightforward is that the collections endpoint also changed structure. The flat `/api/v2/collections` path returns an empty response with no error and no content. Not an empty array. Not a 404. Just nothing.

```bash
curl -s http://localhost:8000/api/v2/collections | python3 -m json.tool
```

```
Expecting value: line 1 column 1 (char 0)
```

The actual path in v1.0.0 requires the full tenant and database hierarchy:

```bash
curl -s http://localhost:8000/api/v2/tenants/default_tenant/databases/default_database/collections
```

```
[]
```

There it is. Documentation doesn't mention this. The error message doesn't help. You find it by reading the ChromaDB v1.0.0 release notes, or by staring at an empty response long enough that you start looking at the source code.

-----

### The Dependency Matrix That pip Couldn't Solve

The original requirements file pinned `langchain==0.3.7`, `langchain-community==0.3.7`, and `langchain-chroma==1.1.0` together. This is the combination that appears in most tutorials as of late 2025. It doesn't work.

`langchain-chroma 1.1.0` depends on `langchain-core>=1.2.0`. `langchain 0.3.7` depends on `langchain-core<1.0.0`. These two requirements cannot be satisfied simultaneously. pip says so directly:

```
ERROR: Cannot install because these package versions have conflicting dependencies.
ERROR: ResolutionImpossible
```

The resolution is to drop the explicit `langchain` pin entirely and let pip resolve it as a transitive dependency. The packages that actually need to be pinned are the ones with direct imports in the code: `langchain-chroma`, `langchain-ollama`, and `langchain-huggingface`. Everything else resolves automatically.

What also happened during dependency resolution: `langchain_community.vectorstores.Chroma` is deprecated as of LangChain 0.2.9. `langchain_community.embeddings.SentenceTransformerEmbeddings` is deprecated as of LangChain 0.2.2. The replacements are `langchain_chroma` and `langchain_huggingface` respectively -- separate packages that pip doesn't install automatically with `langchain-community`. If you follow tutorials written before mid-2025, you'll get working code covered in deprecation warnings pointing at classes scheduled for removal.

Similarly, `langchain.chains.RetrievalQA` -- the standard RAG chain in every example -- throws a `ModuleNotFoundError` against the current `langchain-core` because `langchain_core.memory` was removed. The modern equivalent is the LCEL (LangChain Expression Language) chain syntax, which composes retrieval and generation as a pipeline. It's cleaner once you've read the docs for it.

-----

### The CUDA Problem on a Machine With No GPU

The original plan was to run the RAG service in a Docker container, same as everything else. This required building an image with `sentence-transformers` for the embedding model.

`sentence-transformers` depends on PyTorch. PyTorch on Linux comes with CUDA bindings whether you want them or not. The full install is approximately 3GB. The NUC has a 39GB disk. After three weeks of Docker images, the free space was down to 5.2GB.

The build fails at the layer extraction stage:

```
ERROR: failed to extract layer: write .../nvidia/cu13/lib/libnvrtc.so.13:
no space left on device
```

Freeing Docker's unused images and build cache recovered about 4GB. The build failed again. The overlay filesystem used by containerd requires more contiguous space than the raw numbers suggest.

The actual fix is to not use PyTorch at all. ChromaDB ships with a built-in embedding function that uses `onnxruntime` -- same model (`all-MiniLM-L6-v2`), same 384-dimension output vectors, about 80MB instead of 3GB. No GPU support, no CUDA, no disk space problem.

The further fix is to not use a Docker container for the RAG service at all. Running uvicorn directly on the host sidesteps the entire image build problem. The service has three source files and eight dependencies. A process manager like systemd or supervisor handles restart behavior. For a single-machine lab, this is simpler and more transparent than a container.

-----

### The Embedding Mismatch

Getting ChromaDB to store documents is straightforward. Getting it to retrieve them correctly is where the first serious problem appeared.

The ingestion script initially used ChromaDB's native `DefaultEmbeddingFunction` -- the onnxruntime path -- to populate the collection. The RAG service used LangChain's `Chroma` vectorstore, which uses its own default embedding path when no function is specified. These two paths produce vectors in different formats.

When the retriever queries the collection, ChromaDB compares query vectors against stored vectors that were generated by a different embedding system. The comparison fails, and ChromaDB returns the raw numpy array data in an error message:

```json
{
  "detail": "Expected embeddings to be a list of floats or ints... got [[array([-8.13e-02, 1.67e-02, ...])]"
}
```

Three hundred lines of floating point numbers. Not immediately recognizable as an embedding format mismatch.

The fix is simple in retrospect: use `HuggingFaceEmbeddings` explicitly in both the ingestion script and the service, passing the same model name to both. When both sides use identical embedding functions, the vectors are compatible and retrieval works correctly.

The lesson: in RAG systems, embedding consistency is not optional. Ingest and query must use the same model, same library, same configuration. Mismatches are silent at write time and explosive at read time.

-----

### The Tool Calling Size Problem

Once the RAG service was working correctly via curl, wiring it into Open WebUI surfaced a different class of problem.

`qwen2.5:0.5b` and `tinyllama:1.1b` are the approved models for this stack. Both are small enough to run on the NUC's CPU at tolerable speed, or on the desktop GPU at impressive speed. Neither is reliable at tool calling.

Tool calling requires the model to: recognize that a tool exists, decide when to use it, construct a valid JSON function call with the correct parameter names and values, and pass that call to the runtime. At 500M and 1.1B parameters respectively, these models recognize that a tool exists but can't reliably construct the function call arguments. The result is answers that look like the model answered from training data -- because it did. The tool was enabled but never invoked.

When explicitly told to use the tool by name:

"Use the query_knowledge_base tool to answer: what is the procedure when a host is compromised?"

The 0.5B model recognized the tool name and attempted to call it. It reported back that it couldn't call the tool because it didn't have the `question` parameter -- the parameter that was right there in the question it was asked. It then answered from training data anyway, helpfully suggesting the user contact the FBI.

The fix is `qwen2.5:7b`. At 7 billion parameters, the model correctly identifies when to invoke the tool, constructs the function call with the right arguments, and incorporates the retrieved content into its response. The first successful end-to-end query through the full chain -- Open WebUI -> Tool -> RAG service -> ChromaDB -> desktop GPU -> cited answer -- used `desktop/qwen7b` via LiteLLM.

The practical implication: RAG + tool calling has a minimum viable model size. For this stack, that number is somewhere between 500M and 7B parameters. For a production deployment, it's worth knowing that number before choosing your inference backend.

-----

### pip Doesn't Exist Until It Does

Debian 13 ships with Python 3.11. It does not ship with pip. This is a choice the Debian maintainers made and presumably feel good about.

```bash
pip install chromadb
```

```
-bash: pip: command not found
```

Fair enough. Try the other one:

```bash
pip3 install chromadb
```

```
-bash: pip3: command not found
```

Also not there. Try the Python module path:

```bash
python3 -m pip install chromadb
```

```
/usr/bin/python3: No module named pip
```

Python exists. pip does not. Install it:

```bash
sudo apt-get install -y python3-pip --fix-missing 2>&1 | tail -5
```

The `linux-libc-dev` package fails to fetch from the security repo with a 404 -- the package version referenced in the sources list no longer exists at that URL. This is a stale repo entry, not a broken system. The `--fix-missing` flag tells apt to install everything it can and skip what it can't. pip installs successfully. The linux-libc-dev failure is noise.

Verify:

```bash
python3 -m pip --version
```

```
pip 23.0.1 from /usr/lib/python3/dist-packages/pip (python 3.11)
```

Note the invocation going forward is `python3 -m pip`, not `pip` or `pip3`. Neither of those symlinks exists on this machine. Every install command in this episode uses the module form.

-----

### The LiteLLM Config That Duplicated Itself

Adding `qwen2.5:7b` to the LiteLLM config turned into a small adventure in shell redirection.

The config file at `/opt/litellm/config.yaml` is owned by root. The first attempt used `cat >>` to append the new model entry:

```bash
cat >> /opt/litellm/config.yaml << 'EOF'
  - model_name: desktop/qwen7b
    litellm_params:
      model: ollama/qwen2.5:7b
      api_base: http://192.168.38.215:11434
EOF
```

```
-bash: /opt/litellm/config.yaml: Permission denied
```

Right. Sudo:

```bash
sudo tee -a /opt/litellm/config.yaml << 'EOF'
  - model_name: desktop/qwen7b
...
EOF
```

This ran without error. The problem was invisible until `cat /opt/litellm/config.yaml` showed the result -- the new model entry landed inside the `litellm_settings` block, not the `model_list` block. Invalid YAML, wrong section.

Running `sudo tee` again to fix it made things worse. `tee` without `-a` overwrites. `tee -a` appends. Running it again with the intent to overwrite but forgetting to drop the `-a` flag produced a file with the entire config duplicated twice, broken content and all.

The fix was to abandon shell redirection entirely and write the file with Python, which doesn't care about heredoc quirks or append flags:

```bash
sudo python3 -c "
content = '''model_list:
  - model_name: nuc/tinyllama
    litellm_params:
      model: ollama/tinyllama:1.1b
      api_base: http://ollama:11434
  - model_name: desktop/qwen7b
    litellm_params:
      model: ollama/qwen2.5:7b
      api_base: http://192.168.38.215:11434

litellm_settings:
  drop_params: true
  callbacks:
    - presidio
  output_parse_pii: true
'''
open('/opt/litellm/config.yaml', 'w').write(content)
print('Done')
"
```

27 lines. One `model_list` block. One `litellm_settings` block. `desktop/qwen7b` in the right place.

The lesson: when appending to YAML files with heredocs, always verify the full file contents immediately after. YAML cares deeply about indentation and block structure. Shell redirection does not.

-----

### The Presidio Surprise

When switching from the local Ollama models to `desktop/qwen7b` via LiteLLM, the first attempt returned:

```json
{"error": {"message": "Cannot connect to host presidio-analyzer:3000 ssl:default [Name or service not known]"}}
```

Presidio had been running fine when LiteLLM was last active. What changed is that the Presidio containers exited three days ago -- the no-restart-policy finding from Episode 3.3A, still taking victims. LiteLLM's Presidio callback fires on every request and fails hard when Presidio is unreachable.

Starting the containers solved it:

```bash
docker start presidio-analyzer presidio-anonymizer
```

Thirty seconds for the spaCy models to load, then healthy. This is documented as a finding in 3.3A and will be fixed in Fix Cluster 1. For now, it's a manual restart every time the machine reboots.

-----

## Software Versions

The versions that actually work together on this machine, after resolving conflicts:

|Component            |Version                        |Notes                                                                           |
|---------------------|-------------------------------|--------------------------------------------------------------------------------|
|ChromaDB server      |1.0.0                          |v2 API -- use /api/v2/ paths throughout                                          |
|chromadb client      |1.5.5                          |Client newer than server -- compatible                                           |
|langchain-chroma     |1.1.0                          |Replaces deprecated langchain_community.vectorstores.Chroma                     |
|langchain-ollama     |1.0.1                          |Replaces 0.2.0 -- version conflict forced upgrade                                |
|langchain-huggingface|1.2.1                          |Replaces deprecated langchain_community.embeddings.SentenceTransformerEmbeddings|
|langchain-core       |1.2.23                         |Resolved automatically -- do not pin                                             |
|FastAPI              |0.115.0                        |RAG service framework                                                           |
|uvicorn              |0.30.6                         |ASGI server -- runs on host directly                                             |
|Ollama               |0.1.33 (NUC) / 0.17.7 (Desktop)|LLM backend                                                                     |
|Open WebUI           |v0.6.33                        |Tool registration via Workspace -> Tools                                        |
|qwen2.5:7b           |--                              |Minimum viable model for reliable tool calling                                  |

-----

## Sources and References

### Research

|Source                                                                     |Reference                                                                                                                       |
|---------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|
|PoisonedRAG -- Zou et al. 2024 (90% manipulation rate with 5 injected docs) |[arxiv.org/abs/2402.07867](https://arxiv.org/abs/2402.07867)                                                                    |
|UpGuard -- 1,170 exposed ChromaDB instances, 406 with live data (April 2025)|[upguard.com/blog/open-chroma-databases-ai-attack-surface](https://www.upguard.com/blog/open-chroma-databases-ai-attack-surface)|
|ChromaDB -- authentication in v1.0.x                                        |[cookbook.chromadb.dev/security/auth-1.0.x](https://cookbook.chromadb.dev/security/auth-1.0.x/)                                 |
|ChromaDB -- v1.0.0 release and API changes                                  |[docs.trychroma.com](https://docs.trychroma.com)                                                                                |
|LangChain -- LCEL retrieval chain documentation                             |[python.langchain.com/docs/how_to/qa_sources](https://python.langchain.com/docs/how_to/qa_sources/)                             |

### Compliance Frameworks

|Framework                    |Reference                                                                                                                         |
|-----------------------------|----------------------------------------------------------------------------------------------------------------------------------|
|NIST SP 800-53 Rev. 5        |[csrc.nist.gov/pubs/sp/800/53/r5/upd1/final](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)                                  |
|SOC 2 Trust Services Criteria|[aicpa-cima.com/resources/download/trust-services-criteria](https://www.aicpa-cima.com/resources/download/trust-services-criteria)|
|PCI DSS v4.0.1               |[pcisecuritystandards.org/standards/pci-dss](https://www.pcisecuritystandards.org/standards/pci-dss/)                             |
|CIS Controls v8.1            |[cisecurity.org/controls/v8-1](https://www.cisecurity.org/controls/v8-1)                                                          |
|OWASP LLM Top 10 (2025)      |[genai.owasp.org/llm-top-10](https://genai.owasp.org/llm-top-10/)                                                                 |

-----



*(C) 2026 Oob Skulden(TM) | AI Infrastructure Security Series | Episode 3.4A*

*Next: Episode 3.4B -- The knowledge base is running. Everyone trusts the citations. Here's what happens when we add five documents of our own.*
