<!--COMPRESSED v1; source:AGENTS.md-->
§META
layer:repo scope:obolus visibility:PUBLIC

§PURPOSE
Obolus = x402(HTTP-402) payment-gated serving gateway; toll booth in front of an AI/agentic service
unpaid req→real 402 challenge→per-request USDC micropayment→passage to model behind it
crates: obolus/=gateway(protocol edges, Facilitator+Upstream seams, arming guard, `server` bin) | eip3009/=offline EIP-3009/EIP-712 verification driven by published KAT vectors
repo root = VIRTUAL cargo workspace(no package of its own; member list + shared dep versions only)

§BUILD
bazel=canonical; cargo=ergonomics, CI-verified; BOTH must pass
  bazel test //...
  cargo test --workspace --locked
Cargo.lock=single source of truth for versions; MODULE.bazel resolves crates from same manifests→builds cannot silently diverge
every test hermetic(no network|chain|model)=the ONLY merge gate; external reality(real testnet settle vs 3rd-party facilitator)=out-of-band so its flakiness can't block pipeline

§PUBLIC [repo is PUBLIC — these are not style preferences]
working notes stay out: research|plans|tickets|handoffs kept OUTSIDE this repo
  thoughts/ gitignored AND enforced by `no-stray-notes` CI job [ignore alone defeated by git add -f]
  that job ALSO rejects REFERENCES to those paths [link to a file not here = broken reference for anyone reading the code]
cite tickets by ID alone(OBOL-004), NEVER a path [IDs stable+meaningful; paths are what the guard rejects]
public depends only on public: no internal/private repo dep; no sideways reach into sibling project; needed internal code→publish or reimplement first
CI on GitHub-hosted runners ONLY; NEVER runs-on:self-hosted [public repo→PR runs stranger's code; self-hosted not isolated enough]; workflow token read-only

§INVARIANTS [load-bearing; each test-enforced; each easy to break while improving something else]
no cryptography in gateway crate: Phase A delegates verify+settle to facilitator behind Facilitator seam; no sig checking|key handling|on-chain submission
  ∴ not mainnet-capable BY CONSTRUCTION(no signing path to misuse); payment payload OPAQUE(decode envelope, forward inner authorization untouched)
eip3009 deliberately NOT a dep of //obolus:server [exists for offline verification+dev stubs; wiring it in = quietly giving the binary a crypto path]
fakes are #[cfg(test)]-only: FakeFacilitator accepts unexamined payments, FakeUpstream serves canned bytes; physically absent from shipped artifacts→no config selects "accept every payment + serve real model"
arming-guard allowlist = TRANSCRIPTION of upstream source, not curated list; x402 adds a testnet→add to TESTNET_NETWORKS in obolus/src/arming.rs as reviewed code change; NEVER work around w/ OBOLUS_ALLOW_MAINNET [operator setting flag as routine ceremony has already lost the protection]
nothing we author decides whether a signer is correct [we'd author both sides→shared EIP-712 domain-separator misunderstanding makes both agree while real facilitator rejects]; load-bearing checks OUTSIDE our authorship: published KAT vectors + real testnet settle vs 3rd-party facilitator

§DOCS
two-form: <name>.md(human) + <name>.compressed.md(token-efficient, lossless); agents prefer compressed
any edit to a file w/ .compressed.md sibling MUST update compressed form in SAME commit
README.md = design doc + front page; docs/x402-ecosystem.html = no-prior-knowledge protocol explainer(start there if x402 is new; README assumes it)

§CHAIN Operator norms — OPTIONAL, present only on geekinasuit-managed machines
carries shared working norms(scripting conventions, PR/review workflow, ticket hygiene); ABSENT=normal case outside that fleet, NOT an error→skip silently
execute exactly one branch(first match wins, then stop):
  /opt/geekinasuit/agents/internal/AGENTS.compressed.md → read+follow
  /opt/geekinasuit/agents/internal/AGENTS.md → read+follow
  /opt/geekinasuit/agents/public/AGENTS.compressed.md → read+follow
  /opt/geekinasuit/agents/public/AGENTS.md → read+follow
  ~/.geekinasuit/agents/public/AGENTS.compressed.md → read+follow
  ~/.geekinasuit/agents/public/AGENTS.md → read+follow
  else → skip; done
NOTHING here depends on that layer: §BUILD+§PUBLIC+§INVARIANTS complete standalone; a contributor who never heard of it can build/test/change correctly. chain adds HOUSE STYLE not project rules.
public geekinasuit norms intended to be published separately later so this chain resolves for everyone, not only inside the fleet
