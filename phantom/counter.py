import logging
from dataclasses import dataclass, asdict
from enum import Enum
from phantom.classifier import ClassificationResult, HoneypotPlatform
from phantom.topology import TopologyReport, DeceptionStrategy

logger = logging.getLogger("phantom.counter")

class PortDisposition(str, Enum):
    PRIORITIZE  = "PRIORITIZE"
    INVESTIGATE = "INVESTIGATE"
    AVOID       = "AVOID"
    CANARY_RISK = "CANARY_RISK"
    UNKNOWN     = "UNKNOWN"

@dataclass
class PortRecommendation:
    port: int
    proto: str
    disposition: PortDisposition
    reason: str
    confidence: float

@dataclass
class CounterPlaybook:
    host: str
    strategy_summary: str
    threat_level: str
    approach: str
    port_recommendations: list
    avoid_ports: list
    prioritize_ports: list
    canary_risk_ports: list
    lanimals_risk_score: float
    lanimals_tags: list
    operator_notes: list

    def to_dict(self):
        return asdict(self)

    def summary_lines(self):
        return [
            f"  Host          : {self.host}",
            f"  Strategy      : {self.strategy_summary}",
            f"  Threat Level  : {self.threat_level}",
            f"  LANimals Risk : {self.lanimals_risk_score:.2f}",
            f"  Approach      : {self.approach}",
            f"  Prioritize    : {self.prioritize_ports or chr(39)+chr(39)}none confirmed{chr(39)+chr(39)}",
            f"  Avoid         : {self.avoid_ports[:20]}",
            f"  Canary Risk   : {self.canary_risk_ports or "none"}",
        ]

CANARY_PLATFORMS = {HoneypotPlatform.THINKST, HoneypotPlatform.OPENCANARY}

class CounterEngine:
    def build(self, topology, classifications, real_ports):
        port_recs, avoid, prioritize, canary = [], [], [], []

        for port, proto in real_ports:
            port_recs.append(PortRecommendation(port, proto, PortDisposition.PRIORITIZE,
                "Confirmed real — banner matched nmap probe signatures.", 0.95))
            prioritize.append(port)

        for cls in classifications:
            disp, reason = self._disposition(cls)
            port_recs.append(PortRecommendation(cls.port, cls.protocol_hint,
                disp, reason, cls.confidence))
            if disp == PortDisposition.AVOID:       avoid.append(cls.port)
            elif disp == PortDisposition.CANARY_RISK: canary.append(cls.port)

        port_recs.sort(key=lambda r: r.port)

        return CounterPlaybook(
            host=topology.host,
            strategy_summary=topology.strategy.value,
            threat_level=topology.threat_level,
            approach=self._approach(topology),
            port_recommendations=port_recs,
            avoid_ports=sorted(set(avoid)),
            prioritize_ports=sorted(set(prioritize)),
            canary_risk_ports=sorted(set(canary)),
            lanimals_risk_score=self._risk_score(topology),
            lanimals_tags=self._tags(topology, classifications),
            operator_notes=self._notes(topology, classifications, real_ports),
        )

    def _disposition(self, cls):
        if cls.platform in CANARY_PLATFORMS:
            return (PortDisposition.CANARY_RISK,
                f"{cls.platform.value} (conf={cls.confidence:.2f}) — interaction triggers alert.")
        if cls.confidence >= 0.40:
            return (PortDisposition.AVOID,
                f"{cls.platform.value} via {cls.matched_signature} (conf={cls.confidence:.2f}).")
        return (PortDisposition.UNKNOWN,
            f"Unclassified fake (conf={cls.confidence:.2f}). Treat with caution.")

    def _approach(self, t):
        approaches = {
            DeceptionStrategy.ALL_PORTS_OPEN:
                "Mass deception active. Use confirmed real port list only. Ignore everything else.",
            DeceptionStrategy.TARPIT:
                "Tarpit detected. Reduce concurrency. Avoid banner-grabbing unknown ports.",
            DeceptionStrategy.MIXED:
                "Mixed env — real services coexist with honeypots. Prioritized ports only.",
            DeceptionStrategy.SELECTIVE_HONEY:
                "Selective honeypots on specific services. Validate any unclassified open port.",
            DeceptionStrategy.SPARSE:
                "Low-density decoys — likely canary tripwires. Proceed normally elsewhere.",
        }
        return approaches.get(t.strategy,
            "Strategy unclear. Treat all fake-classified ports as suspect.")

    def _risk_score(self, t):
        base = t.fake_ratio * 0.6
        bonus = {
            DeceptionStrategy.ALL_PORTS_OPEN: 0.35,
            DeceptionStrategy.TARPIT: 0.25,
            DeceptionStrategy.MIXED: 0.15,
            DeceptionStrategy.SELECTIVE_HONEY: 0.10,
            DeceptionStrategy.SPARSE: 0.05,
        }.get(t.strategy, 0.0)
        canary_bonus = 0.10 if t.dominant_platform in (
            HoneypotPlatform.THINKST, HoneypotPlatform.OPENCANARY) else 0.0
        return min(1.0, base + bonus + canary_bonus)

    def _tags(self, topology, classifications):
        tags = ["phantom-analyzed"]
        if topology.strategy == DeceptionStrategy.ALL_PORTS_OPEN: tags.append("all-ports-open")
        if topology.strategy == DeceptionStrategy.TARPIT:         tags.append("tarpit")
        if topology.tarpit_suspected:                              tags.append("slow-responder")
        for c in classifications:
            if c.platform != HoneypotPlatform.UNKNOWN_FAKE:
                tags.append(f"platform:{c.platform.value.lower().replace(' ','-')}")
        if topology.high_confidence_fakes > 10: tags.append("high-density-deception")
        elif topology.high_confidence_fakes > 0: tags.append("confirmed-honeypots")
        return list(dict.fromkeys(tags))

    def _notes(self, topology, classifications, real_ports):
        notes = []
        if not real_ports:
            notes.append("WARNING: No real services confirmed on scanned ports.")
        thinkst = [c.port for c in classifications if c.platform == HoneypotPlatform.THINKST]
        if thinkst:
            notes.append(f"Thinkst Canary on port(s) {thinkst} — interaction already logged.")
        cowrie = [c.port for c in classifications if c.platform == HoneypotPlatform.COWRIE]
        if cowrie:
            notes.append(f"Cowrie SSH on port(s) {cowrie} — credentials harvested here.")
        if topology.strategy == DeceptionStrategy.ALL_PORTS_OPEN:
            notes.append("All-ports-open consistent with s0i37/defence technique.")
        return notes
