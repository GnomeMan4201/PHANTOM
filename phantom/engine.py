import logging, time
from dataclasses import dataclass, asdict
from typing import Optional
from phantom.classifier import HoneypotClassifier
from phantom.topology import TopologyMapper, PortRecord
from phantom.counter import CounterEngine

logger = logging.getLogger("phantom.engine")

@dataclass
class PhantomReport:
    host: str
    scan_time_s: float
    topology: object
    classifications: list
    playbook: object

    def to_dict(self):
        return {
            "host": self.host,
            "scan_time_s": self.scan_time_s,
            "topology": self.topology.to_dict(),
            "classifications": [c.to_dict() for c in self.classifications],
            "playbook": self.playbook.to_dict(),
        }

class PhantomEngine:
    def __init__(self):
        self.classifier     = HoneypotClassifier()
        self.topology_mapper = TopologyMapper()
        self.counter_engine  = CounterEngine()

    def analyze(self, host, scan_results):
        t0 = time.time()
        real_ports, fake_inputs, port_records = [], [], []

        for is_real, port, proto, banner, timing_ms in scan_results:
            port_records.append(PortRecord(port, proto, is_real, banner, timing_ms))
            if is_real:
                real_ports.append((port, proto))
            else:
                fake_inputs.append((port, proto, banner, timing_ms))

        classifications = self.classifier.classify_batch(fake_inputs)
        cls_map = {c.port: c for c in classifications}
        for pr in port_records:
            if not pr.is_real and pr.port in cls_map:
                pr.classification = cls_map[pr.port]

        topology = self.topology_mapper.analyze(host, port_records)
        playbook = self.counter_engine.build(topology, classifications, real_ports)

        return PhantomReport(host, time.time() - t0, topology, classifications, playbook)

    @staticmethod
    def parse_decoy_hunter_output(raw, host):
        results = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not (line.startswith("[REAL]") or line.startswith("[FAKE]")):
                continue
            try:
                is_real = line.startswith("[REAL]")
                parts = line.split()
                port = int(parts[1].split("/")[0])
                proto = parts[1].split("/")[1]
                banner = line.split("→", 1)[1].strip().encode() if "→" in line else b""
                results.append((is_real, port, proto, banner, None))
            except Exception:
                continue
        return results
