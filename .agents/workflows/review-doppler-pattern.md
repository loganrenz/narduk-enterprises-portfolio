---
description: Audit the Doppler secret management pattern for completeness, agent-clarity, and security
---

You are tasked with reviewing the Doppler "Hub and Spoke" secret management pattern within this repository. 
Your goal is to ensure the pattern is bulletproof, secure, and documented so clearly that any autonomous AI agent or human developer can seamlessly use it without making mistakes or leaking secrets.

### Scope of Review
Please analyze the following touchpoints:
1. **`AGENTS.md`**: Is the hub-and-spoke architecture explicitly documented? Does it provide a clear table of which secrets belong to the hub vs. the app spoke? Are cross-project reference syntaxes (`${project.config.SECRET}`) explicitly shown? Does it explain `dev` vs `prd` configs?
2. **`README.md`**: Are the quick-start commands accurate, non-interactive (e.g., passing explicit `--project` and `--config` flags to `doppler setup`), and easy to copy-paste?
3. **`.gitignore`**: Are Doppler-specific environment files properly ignored? Check for `.env`, `doppler.json`, and crucially, the interactive local state file `doppler.yaml`.
4. **`tools/init.ts`**: Review the automated workspace provisioning. Are secrets synced additively? Are the terminal instructions output at the end of the script safe and non-interactive?
5. **CI/CD (`.github/workflows/deploy.yml`)**: Is the Doppler CLI installed properly? Are secrets fetched and injected securely (`>> $GITHUB_ENV`)? Is this intentional injection pattern documented with a code comment so agents don't flag it as an accidental leak vector?
6. **`nuxt.config.ts` (Workspace & Apps)**: Does the `runtimeConfig` map to raw env var names (e.g. `process.env.POSTHOG_PUBLIC_KEY`) rather than relying on automatic `NUXT_` mapping, and is the documentation aligned with reality?

### Evaluation Criteria
* **Agent-Clarity**: If an AI agent reads the repository, will it instantly know how to bind a new secret from a hub or persist a local secret without interacting with a human?
* **Non-Interactive Execution**: Ensure all terminal commands recommended in docs or printed by scripts do not hang waiting for interactive user input (e.g., `doppler setup` vs `doppler setup --project xyz --config dev`).
* **Isolation Constraints**: Ensure that nothing encourages committing `doppler.yaml`, which would break the spoke isolation model by forcing all developers onto the same configuration.

### Expected Actions
1. Produce a detailed critique of the current state based on the criteria above.
2. Outline specific, actionable fixes for any identified gaps.
3. Apply these fixes to the relevant files.
4. Verify consistency across the documentation, `.gitignore`, and automation scripts.
