# Agent-Sentinel Architecture & Technical Specification

## 1. System Overview & Dual-Path Architecture

AI coding agents (such as Claude Code, Cursor, Open-Interpreter, and Aider) frequently run shell commands autonomously. While traditional security controls rely on static regex blacklists (easily bypassed by obfuscation) or multi-second LLM audits (adding 2000ms+ latency), **Agent-Sentinel** enforces strict security inspection under a **35ms latency ceiling** with **$0 token cost**.

```
[AI Coding Agent (Claude Code / Cursor)]
              │
              ▼  (intercepted via MCP Security Proxy or CLI Shim)
┌─────────────────────────────────────────────────────────────┐
│                   Agent-Sentinel Gateway                    │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ L1 Fast-Path Filter (Deterministic Regex & Trie)     │  │
│  │ - Safe Whitelist: git status, ls, pwd...   -> ALLOW   │  │
│  │ - Hard Blacklist: rm -rf /, :(){ :|:& };:  -> BLOCK   │  │
│  │ - Latency: < 0.05 ms (Handles ~80% of commands)       │  │
│  └──────────────────────────┬────────────────────────────┘  │
│                             │ Non-deterministic / Sensitive │
│                             ▼                               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Shell AST Pruner & Obfuscation Scanner                │  │
│  │ - Base64 decode / eval / dynamic execution flags      │  │
│  │ - Network call & filesystem mutation slicing          │  │
│  │ - Token budget compression (avoids >200ms prefill)    │  │
│  └──────────────────────────┬────────────────────────────┘  │
│                             ▼                               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ L2 Calibrated Semantic Decision Kernel (AnyJev)       │  │
│  │ - Nokia Applied Research AnyJev Decider / Tacit       │  │
│  │ - Single-Forward Prefill (Qwen2.5-Coder-1.5B/3B)      │  │
│  │ - Typed outputs: P(ALLOW), P(BLOCK), P(CONFIRM)       │  │
│  │ - Latency: ~18-25 ms                                  │  │
│  └──────────────────────────┬────────────────────────────┘  │
│                             ▼                               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Policy Decision Router                                │  │
│  │ - P(ALLOW) > 0.90 & No Hazard Flags -> 0-Latency Pass │  │
│  │ - P(BLOCK) >= 0.10 or Destructive   -> Halt Agent     │  │
│  │ - Ambiguous Grey Zone               -> Human Confirm  │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. AnyJev Decision Primitives & Single-Forward Optimization

### 2.1 The Bias Problem in Zero-Shot LLM Probabilities
Standard open causal LLMs exhibit strong **Positional Bias** (favoring options appearing first or last in the prompt) and **Label Prior Bias** (favoring specific tokens like 'A' regardless of context).

Under Nokia's AnyJev formulation, given an input $x$ and option set $C = \{c_1, \dots, c_K\}$, unbiased probabilities are normally recovered via cyclic permutations $\pi_k(C)$:
$$P(y = c \mid x) \propto \frac{\prod_{k=1}^K P_{\text{LLM}}(c \mid x, \pi_k)^{1/K}}{P_0(c)}$$

### 2.2 The Latency Trap & The 35ms SLA
Running $K$ forward passes (e.g., $K=3$ for `[ALLOW, BLOCK, REQUIRE_HUMAN_CONFIRM]`) triples the prefill computation:
$$\text{Latency} \approx 3 \times 20\text{ms} = 60\text{ms}$$
This violates the 35ms human-imperceptible budget.

**Agent-Sentinel's Solution:**
1. **Offline Prior Pre-computation**: We estimate the prior vector $P_0(c)$ ahead of time on representative developer commands.
2. **Single-Forward Pass ($N=1$)**: During runtime inference, we execute strictly **one** forward prefill pass with normalized prior subtraction.
3. **Tacit Distilled Checkpoints**: Direct support for Nokia's self-distilled `Tacit` weights, enabling single-pass calibrated decision logits.

---

## 3. Interception Engineering: Why `preexec` Is Not Enough

| Interception Method | Mechanism | Agent Compatibility | Penetration Risk |
|---|---|---|---|
| **Bash/Zsh `preexec`** | Interactive shell trap | Poor (Agents execute non-interactive `bash -c`) | **High** (Subshells bypass `.bashrc`) |
| **MCP Security Proxy** | Middleware implementing Anthropic MCP standard | **Native** (Claude Code, Cursor, Windsurf) | **Zero** (Tool calls are strictly intercepted) |
| **CLI Shim Wrapper** | Symlinked binary wrapper replacing `/bin/bash` | Universal for CLI subprocess spawners | **Low** (Requires PATH priority or container mount) |
| **Linux `seccomp-bpf`** | Kernel syscall filtering (`execve`, `socket`) | Universal (Linux only) | **Zero** (Heavy configuration overhead) |

**Production Recommendation:**
- **Primary:** Deploy the **MCP Security Proxy** for Claude Code and Cursor.
- **Secondary:** Deploy the **CLI Shim** for legacy CLI agents using `subprocess.Popen(["bash", "-c", ...])`.

---

## 4. AST Pruning & Token Budget Defense (Fail-Closed Architecture)

### The Security Dilemma
When an agent submits a 2,000-line build script or complex installation pipeline, prefill latency exceeds 200ms. However, **naive line deletion is an attack vector**:
- Attackers hide destructive payloads via environment variable concatenation: `${CMD_PART_1}${CMD_PART_2}`.
- Attackers decode commands in-memory: `echo <base64> | base64 -d | sh`.

### Sentinel's Defense-in-Depth Pruner
1. **Dynamic Execution & Obfuscation Detection:**
   - Detects `base64 -d`, `eval`, `exec`, `xxd -r`, `/dev/tcp/*`, and subshell pipe chains.
   - If detected, `is_obfuscated = True` is immediately asserted. Obfuscated snippets are **never discarded**.
2. **Critical Node Extraction:**
   - Extracts network invocations (`curl`, `wget`, `nc`, `ssh`) and filesystem mutations (`rm`, `mv`, `dd`, `chmod`).
   - Slices out safe boilerplate (comments, repetitive echoes, build logs).
3. **Fail-Closed Budgeting:**
   - If the script exceeds token budget after pruning, it sets `is_truncated = True`, forcing ambiguous scripts to `REQUIRE_HUMAN_CONFIRM` rather than risking a false negative.
