# Model advisory providers

Intent Gate can request a second, model-generated determination after the deterministic policy returns. Model output is **advisory only**: it cannot execute a command, approve a review, weaken a deterministic block, or delay the CLI enforcement path.

## Provider contract

Every provider receives a bounded, redacted context containing the command, declared purpose, project and Git state, privilege, recent activity, external posture, and deterministic assessment. It must return:

```json
{
  "recommended_decision": "review",
  "risk_score": 62,
  "confidence": 0.88,
  "intent_alignment": "unclear",
  "summary": "The action has an external side effect and needs confirmation.",
  "reasons": ["The target environment is not identified by the declared purpose."]
}
```

Responses are schema-checked and normalized before display. Failures, timeouts, missing credentials, invalid JSON, or unsupported classifications do not affect deterministic policy.

## Demo Simulation

The local showcase defaults to a clearly labeled simulation provider when no integration environment file overrides it:

```env
UIG_MODEL_PROVIDER=demo
UIG_MODEL_NAME=intent-advisor-demo
```

It generates schema-valid advisory output locally from the deterministic evidence, adds a short presentation-friendly inference delay, and never contacts an external model. The console labels the provider and every determination as a demo simulation. Use this only for demonstrations and switch to one of the providers below for genuine independent model analysis.

## OpenAI

The OpenAI adapter uses the Responses API with Structured Outputs:

```env
UIG_MODEL_PROVIDER=openai
UIG_MODEL_NAME=gpt-5.6-luna
UIG_MODEL_BASE_URL=https://api.openai.com/v1
UIG_MODEL_API_KEY=replace-with-an-api-key
UIG_MODEL_TIMEOUT_SECONDS=12
```

An OpenAI API key is separate from a ChatGPT subscription. Keep it in an ignored `.env.integrations` file or an approved secret store; never commit it.

## OpenAI-compatible local or hosted model

Use an endpoint that implements `POST /v1/chat/completions` and JSON-schema response formatting:

```env
UIG_MODEL_PROVIDER=openai-compatible
UIG_MODEL_NAME=local-model-name
UIG_MODEL_BASE_URL=http://host.docker.internal:8000/v1
UIG_MODEL_API_KEY=
```

Compatibility varies by server. The adapter fails closed to “advisor unavailable” when the server does not honor the response schema.

## Generic model gateway webhook

Use a gateway for Anthropic, Google, another frontier provider, or an internal routing service:

```env
UIG_MODEL_PROVIDER=webhook
UIG_MODEL_NAME=enterprise-model-router
UIG_MODEL_BASE_URL=https://model-gateway.example.invalid/v1/intent-assess
UIG_MODEL_API_KEY=replace-with-gateway-token
```

The webhook receives `schema_version`, the system classification instructions, bounded context, and the required response schema. It must return the normalized JSON object shown above.

## Security boundary

- Commands and recent history are redacted for common credential forms before leaving the service.
- Full filesystem paths are reduced to the project directory name.
- The model endpoint is called only by the authenticated console advisory route.
- The deterministic decision is returned and recorded independently.
- Model latency is not included in policy-engine latency.
- Production deployments should add provider-specific data retention, residency, identity, rate-limit, and audit controls.
