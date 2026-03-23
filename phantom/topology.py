import logging, statistics
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Optional
from phantom.classifier import ClassificationResult, HoneypotPlatform

logger = logging.getLogger("phantom.topology")

class DeceptionStrategy(str, Enum):
    ALL_PORTS_OPEN  = "All-Ports-Open Deception"
    SELECTIVE_HONEY = "Selective Honeypot Deployment"
    TARPIT          = "Tarpit / Slow-Response Deception"
    MIXED           = "Mixed Real + Honeypot Environment"
    SPARSE          = "Sparse / Low-Density Decoys"
    UNKNOWN         = "Unknown Deception Strategy"

@dataclass
class PortRecord:
    port: int
    proto: str
    is_real: bool
    banner: bytes
    timing_ms: Optional[float] = None
    classification: Optional[ClassificationResult] = None

@dataclass
class TopologyReport:
    host: str
    total_scanned: int
    real_count: int
    fake_count: int
    fake_ratio: float
    strategy: DeceptionStrategy
    strategy_confidence: float
    dominant_platform: HoneypotPlatform
    platform_distribution: dict
    avg_response_ms: Optional[float]
    tarpit_suspected: bool
    high_confidence_fakes: int
    notes: list

    def to_dict(self):
        d = asdict(self)
        d["strategy"] = self.strategy.value
        d["dominant_platform"] = self.dominant_platform.value
        return d

    @property
    def threat_level(self):
        if self.strategy == DeceptionStrategy.ALL_PORTS_OPEN:
            return "HIGH — active deception infrastructure detected"
        elif self.strategy in (DeceptionStrategy.MIXED, DeceptionStrategy.TARPIT):
            return "MEDIUM — partial or resource-exhaustion deception"
        elif self.strategy == DeceptionStrategy.SELECTIVE_HONEY:
            return "MEDIUM — targeted service honeypots"
        elif self.strategy == DeceptionStrategy.SPARSE:
            return "LOW — minimal decoy presence"
        return "UNKNOWN"

class TopologyMapper:
    ALL_PORTS_THRESHOLD = 0.80
    SPARSE_THRESHOLD    = 0.15
    TARPIT_MS_THRESHOLD = 4000
    MIXED_REAL_MIN      = 3

    def analyze(self, host, port_records):
        if not port_records:
            return self._empty(host)

        total = len(port_records)
        real  = [p for p in port_records if p.is_real]
        fake  = [p for p in port_records if not p.is_real]
        real_count, fake_count = len(real), len(fake)
        fake_ratio = fake_count / total

        timings = [p.timing_ms for p in port_records if p.timing_ms is not None]
        avg_timing = statistics.mean(timings) if timings else None
        tarpit = avg_timing is not None and avg_timing > self.TARPIT_MS_THRESHOLD

        platform_dist = {}
        high_conf = 0
        for p in fake:
            if p.classification:
                n = p.classification.platform.value
                platform_dist[n] = platform_dist.get(n, 0) + 1
                if p.classification.confidence >= 0.80:
                    high_conf += 1

        dominant = self._dominant(platform_dist)
        strategy, conf = self._strategy(fake_ratio, real_count, fake_count, tarpit)
        notes = self._notes(strategy, fake_ratio, real_count, fake_count,
                            tarpit, avg_timing, dominant, platform_dist)

        return TopologyReport(host, total, real_count, fake_count, fake_ratio,
                              strategy, conf, dominant, platform_dist,
                              avg_timing, tarpit, high_conf, notes)

    def _strategy(self, fake_ratio, real_count, fake_count, tarpit):
        if fake_count == 0: return DeceptionStrategy.UNKNOWN, 0.5
        if tarpit:           return DeceptionStrategy.TARPIT, 0.75
        if fake_ratio >= self.ALL_PORTS_THRESHOLD: return DeceptionStrategy.ALL_PORTS_OPEN, 0.90
        if fake_ratio <= self.SPARSE_THRESHOLD:    return DeceptionStrategy.SPARSE, 0.80
        if real_count >= self.MIXED_REAL_MIN and fake_count >= 2:
            return DeceptionStrategy.MIXED, 0.75
        if fake_count >= 2: return DeceptionStrategy.SELECTIVE_HONEY, 0.70
        return DeceptionStrategy.UNKNOWN, 0.40

    def _dominant(self, dist):
        if not dist: return HoneypotPlatform.UNKNOWN_FAKE
        name = max(dist, key=dist.get)
        for p in HoneypotPlatform:
            if p.value == name: return p
        return HoneypotPlatform.UNKNOWN_FAKE

    def _notes(self, strategy, fake_ratio, real_count, fake_count,
               tarpit, avg_timing, dominant, dist):
        notes = []
        if strategy == DeceptionStrategy.ALL_PORTS_OPEN:
            notes.append(f"{fake_ratio*100:.0f}% fake — all-ports-open deception infrastructure.")
            notes.append("Real services masked. Use confirmed real port list only.")
        if tarpit and avg_timing:
            notes.append(f"Avg response {avg_timing:.0f}ms — tarpit suspected.")
        if dominant != HoneypotPlatform.UNKNOWN_FAKE:
            notes.append(f"Dominant platform: {dominant.value}. Distribution: {dist}")
        if strategy == DeceptionStrategy.MIXED:
            notes.append(f"{real_count} real + {fake_count} fake — additive deception.")
        return notes

    def _empty(self, host):
        return TopologyReport(host, 0, 0, 0, 0.0, DeceptionStrategy.UNKNOWN,
                              0.0, HoneypotPlatform.UNKNOWN_FAKE, {}, None,
                              False, 0, ["No port records provided."])
