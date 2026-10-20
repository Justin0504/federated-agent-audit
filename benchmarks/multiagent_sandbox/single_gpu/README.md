# Single-A100 pilot

User explicitly limited this additional host to one GPU. Docker exposes only
physical GPU7 (logical CUDA0), with8CPU/48GBRAM limits. Other seven cards are
not used. Inference is prohibited on the local workstation. Delta remains
unavailable without Kerberos/Duo login; Jetstream v16 continues independently.

Official llama.cpp b11624 CUDA12.8 assets are SHA256 pinned in runtime.json.
Qwen2.5-3B Q4_K_M SHA256 matches Jetstream. Slow direct and streamed transfers
were cancelled; download_model.py checks every HTTP range and the final official
full-file digest before publication. No inference may use partial weights.
The existing PyTorch container lacked the release's required GLIBC2.38; an
isolated Ubuntu24 image supplies compatible system libraries, without upgrading
the host. setup.py records the built imageID and Python dependency freeze.

The first pilot is6developmentcases×no_gate/gate_replan=12episodes using the
same12steps/1024output/8192context as v16. Hardware and numerical backend differ,
so GPU/CPU results and time must not be pooled as an algorithmic improvement.
After complete screening, audit_screen requires all four cells with3cases each,
known outcomes,noformat/caperrors,and>=2/3cleanungatedutility. This stricter
competence screen was declared during development, before formal evaluation.
A passing pilot prepares32disjointcases×5controls=160episodes and executes them
on the same single GPU and same budgets. Failure writesgate_failed.json and
blocks expansion. No semantic privacy efficacy follows from native security
predicates alone. All formal counts remain planned until actual outputs exist.

Run setup.py only on zxlyg2286. Credentials are not stored here. Download/build
logs and raw task traces stay on the remote host; export aggregate evidence only.
