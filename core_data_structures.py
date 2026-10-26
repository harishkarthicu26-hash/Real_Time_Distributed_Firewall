import time
import threading
from typing import List, Optional, Tuple, Dict, Any

class TrieNode:
    def __init__(self):
        self.left: Optional['TrieNode'] = None
        self.right: Optional['TrieNode'] = None
        self._isBanned: bool = False
        self.ruleName: Optional[str] = None

    def setBanned(self, rule: str) -> None:
        self._isBanned = True
        self.ruleName = rule

    def isBanned(self) -> bool:
        return self._isBanned

class BinaryRadixTree:
    def __init__(self):
        self.root: TrieNode = TrieNode()
        self._lock = threading.Lock()

    def insertRule(self, binaryPrefix: str, ruleName: str) -> None:
        with self._lock:
            current = self.root
            for bit in binaryPrefix:
                if bit == '0':
                    if not current.left:
                        current.left = TrieNode()
                    current = current.left
                elif bit == '1':
                    if not current.right:
                        current.right = TrieNode()
                    current = current.right
            current.setBanned(ruleName)

    def checkPacket(self, binaryIp: str) -> Optional[TrieNode]:
        current = self.root
        last_banned: Optional[TrieNode] = current if current.isBanned() else None
        for bit in binaryIp:
            current = current.left if bit == '0' else current.right
            if current is None:
                break
            if current.isBanned():
                last_banned = current
        return last_banned

    def tracePacketWithPath(self, binaryIp: str) -> Tuple[Optional[TrieNode], List[Dict[str, Any]]]:
        current = self.root
        steps: List[Dict[str, Any]] = []
        last_banned_node: Optional[TrieNode] = None
        last_banned_step_count: int = 0

        for idx, bit in enumerate(binaryIp):
            nxt = current.left if bit == '0' else current.right
            has_alt = (current.right is not None) if bit == '0' else (current.left is not None)

            if nxt is None:
                if last_banned_node is not None:
                    steps = steps[:last_banned_step_count]
                    steps[-1]["status"] = "BANNED_MATCH"
                    steps[-1]["ruleName"] = last_banned_node.ruleName
                    return last_banned_node, steps
                else:
                    steps.append({
                        "bitIndex": idx + 1,
                        "bit": bit,
                        "status": "CLEAN_EXIT",
                        "hasAlt": has_alt,
                        "ruleName": None
                    })
                    return None, steps

            current = nxt
            steps.append({
                "bitIndex": idx + 1,
                "bit": bit,
                "status": "TRAVERSED",
                "hasAlt": has_alt,
                "ruleName": current.ruleName if current.isBanned() else None
            })
            if current.isBanned():
                last_banned_node = current
                last_banned_step_count = len(steps)

        if last_banned_node is not None:
            steps = steps[:last_banned_step_count]
            steps[-1]["status"] = "BANNED_MATCH"
            steps[-1]["ruleName"] = last_banned_node.ruleName
            return last_banned_node, steps
        return None, steps

class LogEvent:
    def __init__(self, timestamp: int, droppedIp: str, ruleMatched: str):
        self.timestamp = timestamp
        self.droppedIp = droppedIp
        self.ruleMatched = ruleMatched

class CircularQueue:
    def __init__(self, capacity: int = 8):
        self.capacity, self.head, self.tail, self._size = capacity, 0, 0, 0
        self.buffer: List[Optional[LogEvent]] = [None] * capacity
        self._lock = threading.Lock()

    def enqueue(self, event: LogEvent) -> None:
        with self._lock:
            self.buffer[self.tail] = event
            self.tail = (self.tail + 1) % self.capacity
            if self._size < self.capacity:
                self._size += 1
            else:
                self.head = (self.head + 1) % self.capacity

    def getRecentLogs(self) -> List[LogEvent]:
        with self._lock:
            logs = []
            for i in range(self._size):
                idx = (self.head + i) % self.capacity
                if self.buffer[idx]:
                    logs.append(self.buffer[idx])
            return list(reversed(logs))

class Packet:
    def __init__(self, sourceIp: str, destinationIp: str, binaryIp: str):
        self.sourceIp = sourceIp
        self.destinationIp = destinationIp
        self.binaryIp = binaryIp
        self.timestamp = int(time.time())

    def getBinaryIp(self) -> str:
        return self.binaryIp
