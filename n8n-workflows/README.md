# n8n Workflows

Exported n8n workflow JSON files. Import these into n8n via the UI or CLI.

## Workflows

1. **Agentic** (`RlieZMswNK89cCYK`) — Main Tier-3 analysis pipeline
   - Webhook from Wazuh → Extract IOCs → VirusTotal → Tier-3 LLM (OpenRouter/Gemini/AkashML)
   - Parse & Score → Store in Wazuh indexer → Call bridge for sample fetch

2. **YARAKIN Sample Intake** (`yrkSampleIntake01`) — File upload + analysis
   - Webhook from bridge → Build binary → Submit to YARAKIN
   - Poll for results → Update case document in Wazuh indexer

## Import

```bash
# Via n8n CLI
docker exec n8n n8n import:workflow --input=/path/to/workflows.json
docker exec n8n n8n update:workflow --id=<workflow_id> --active=true
```

## Security

- Workflow JSON may contain credentials (API keys, webhook URLs). **Sanitize before committing.**
- This repo's version has all secrets redacted (replaced with `REDACTED` placeholders).
- Set credentials in n8n's credential store after import.
