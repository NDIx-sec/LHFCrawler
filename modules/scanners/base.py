# base.py
from abc import ABC, abstractmethod

class Scanner(ABC):
    @abstractmethod
    def scan(self, url):
        """Visszaad egy finding dict-et vagy None-t."""
        pass
