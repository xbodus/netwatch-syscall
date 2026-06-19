"""
Full State Manager
"""
from typing import Any, Optional, Callable, TYPE_CHECKING

from .models import (
    ParserEvent,
    State,
    Severity,
)

if TYPE_CHECKING:
    from .state import SyscallState

class FSM:
    def __init__(self, name: str, severity: Optional[Severity] = None):
        self.name: str = name
        self.severity: Severity = severity
        self.current_state: State = State.INIT
        self.transitions: dict[tuple[State, str], tuple[State, Callable[[Any, Any], bool] | None]] = {} # Stored as {(current state, event type): (next state, condition callable)}

    def add_transition(self, from_state: State, event_type: str, to_state: State, conditional: Optional[Callable[[Any, Any], bool]] = None) -> None:
        """Registers a transition from one state to another triggered by an event type with an optional condition"""
        self.transitions[(from_state, event_type)] = (to_state, conditional)

    def transition(self, event_type: str, event_data: ParserEvent, state_store: "SyscallState") -> State:
        """Attemps to transition based on the incoming event type and condition"""
        key = (self.current_state, event_type)

        if key in self.transitions:
            next_state, condition = self.transitions[key]
            if condition is None or condition(event_data, state_store):
                self.current_state = next_state
        
        return self.current_state

    def reset(self) -> None:
        """Resets the state back to the initial state"""
        self.current_state = State.INIT
