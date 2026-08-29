# CyberShield + OpenRouter

CyberShield can use OpenRouter as its remote conversational AI while keeping
its existing evidence-first security engine and Ollama offline fallback.

## 1. Configure the key

Copy `.env.example` to `.env` and set:

```text
CYBERSHIELD_AI_PROVIDER=auto
CYBERSHIELD_AI_MODEL=openrouter/free
CYBERSHIELD_AI_BASE_URL=https://openrouter.ai/api/v1
CYBERSHIELD_AI_API_KEY=YOUR_OPENROUTER_KEY
```

Never commit `.env` or put the API key directly into Python source code.

## 2. What `auto` does

- If an OpenRouter key is configured, OpenRouter is used first.
- If OpenRouter fails or is unavailable, installed Ollama is tried.
- If neither is available, CyberShield returns a controlled AI-unavailable result.

## 3. Free model routing

`openrouter/free` is used by default. OpenRouter selects an available free
model for the request. You can set a specific model ID instead if desired.

## 4. Security boundary

The remote model is an intelligence/explanation layer. It does not receive
permission to execute arbitrary commands or directly decide destructive system
actions. CyberShield's local evidence, policy, containment and response-guard
layers remain authoritative.
