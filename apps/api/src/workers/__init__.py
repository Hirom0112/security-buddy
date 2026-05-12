"""Workers package.

The integration layer — imports broadly but nothing in the app imports from
worker handler modules directly. Routes access the queue via workers.queue.

WorkerSettings (for arq) live in workers.red_team_worker.
"""

from src.workers.red_team_worker import WorkerSettings

__all__ = ["WorkerSettings"]
