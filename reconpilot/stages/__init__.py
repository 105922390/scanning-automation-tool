"""Pipeline stages. Each reads prior-stage state from the Store, runs its tools
through the guarded runner, scope-filters and normalizes results, writes them
back, and reports the diff. Stages are independently runnable and idempotent."""

from .passive_recon import PassiveReconResult, PassiveReconStage, parse_hosts

__all__ = ["PassiveReconStage", "PassiveReconResult", "parse_hosts"]
