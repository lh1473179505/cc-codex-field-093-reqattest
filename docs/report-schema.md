# report schema

```json
{
  "decision": "allow" | "deny",
  "reason_codes": ["..."],
  "kid": "...",
  "audience": "...",
  "method": "...",
  "path": "...",
  "matched_scopes": ["..."],
  "notes": []
}
```

`reason_codes` empty on allow. `matched_scopes` is the sorted intersection.
