"""Base class for all L2 attack simulation modules.

Each attack module inherits from BaseAttack and implements the launch()
method, which sends crafted packets and returns an AttackResult with
metadata about what was sent.
"""

from abc import ABC, abstractmethod

from common.models import AttackResult


class BaseAttack(ABC):
    """Abstract base class for L2 attack simulations.

    Subclasses must set `attack_type` and implement `launch()`.
    """

    attack_type: str = "unknown"

    @abstractmethod
    def launch(self, **kwargs) -> AttackResult:
        """Execute the attack simulation.

        Returns:
            AttackResult with metadata about the attack execution
            (packets sent, duration, start time).
        """
        pass
