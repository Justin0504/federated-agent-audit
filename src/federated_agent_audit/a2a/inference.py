"""Formal inference-gain model for the cross-tenant inference detector.

We model what a recipient principal can infer about a subject's sensitive
attribute $A$ (e.g. has-health-condition) from $k$ converging quasi-identifier
fragments. Treating each fragment as conditionally-independent evidence with
likelihood ratio $\\lambda = P(\\text{fragment}\\mid A)/P(\\text{fragment}\\mid\\neg A)$,
the recipient's posterior \\emph{odds} multiply:
\\[ O_k = O_0 \\cdot \\lambda^{k}, \\qquad O_0 = \\frac{p_0}{1-p_0}, \\]
so the posterior belief is $P(A\\mid k) = O_k/(1+O_k)$ and the \\emph{inference
gain} is $g(k) = P(A\\mid k) - p_0$. The detector fires when $g(k)\\ge\\delta$, i.e.
when the recipient's provable belief gain crosses the policy threshold. This
replaces the earlier heuristic $1-2^{-k}$ with a calibrated Bayesian quantity and
yields a closed-form detection bound (Prop.~below).

Proposition. With prior $p_0$, per-fragment likelihood ratio $\\lambda>1$, and
threshold $\\delta$, the detector fires iff
\\[ k \\;\\ge\\; k^\\* = \\Big\\lceil \\log_\\lambda\\frac{O_\\delta}{O_0} \\Big\\rceil,
\\quad O_\\delta = \\frac{p_0+\\delta}{1-p_0-\\delta}. \\]
For the defaults below ($p_0{=}0.1,\\lambda{=}3,\\delta{=}0.3$), $k^\\*=2$: a single
incidental hint never fires, two converging fragments do.
"""

from __future__ import annotations

import math

# Base rate of the sensitive attribute, per-fragment likelihood ratio, and the
# policy gain threshold. Calibrated so k*=2 (one hint tolerated, two convergent
# fragments flagged); deployments can tune them.
PRIOR = 0.1
LIKELIHOOD_RATIO = 3.0
GAIN_THRESHOLD = 0.3


def posterior(k: int, prior: float = PRIOR, lr: float = LIKELIHOOD_RATIO) -> float:
    """Recipient's posterior belief in the sensitive attribute after k fragments."""
    odds = (prior / (1 - prior)) * (lr ** k)
    return odds / (1 + odds)


def inference_gain(k: int, prior: float = PRIOR, lr: float = LIKELIHOOD_RATIO) -> float:
    """Increase in the recipient's belief over the prior: P(A|k) - p0."""
    return posterior(k, prior, lr) - prior


def gain_from_lambdas(lambdas, prior: float = PRIOR) -> float:
    """Inference gain from a set of per-fragment likelihood ratios (odds multiply).

    Generalizes ``inference_gain`` to non-uniform evidence: a single
    high-specificity hint (large λ) can cross the threshold alone, while several
    weak hints must accumulate. With every λ equal to the default it reproduces
    ``inference_gain(k)`` exactly, so calibrated thresholds are preserved.
    """
    odds = prior / (1 - prior)
    for lam in lambdas:
        odds *= lam
    return odds / (1 + odds) - prior


def fragments_to_fire(prior: float = PRIOR, lr: float = LIKELIHOOD_RATIO,
                      delta: float = GAIN_THRESHOLD) -> int:
    """k* — the smallest number of converging fragments that crosses the gain
    threshold (the closed-form detection bound)."""
    o_delta = (prior + delta) / (1 - prior - delta)
    o_0 = prior / (1 - prior)
    return max(1, math.ceil(math.log(o_delta / o_0) / math.log(lr)))
