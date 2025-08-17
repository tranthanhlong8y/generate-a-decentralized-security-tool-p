import hashlib
import json
from collections import defaultdict

class DecentralizedSecurityToolParser:
    def __init__(self, node_network):
        self.node_network = node_network
        self.security_event_logs = defaultdict(list)

    def parse_security_events(self, security_event_data):
        for event in security_event_data:
            event_hash = hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()
            self.security_event_logs[event_hash].append(event)

    def get_security_event_log(self, event_hash):
        return self.security_event_logs.get(event_hash, [])

    def broadcast_security_event(self, event):
        for node in self.node_network:
            node.parse_security_events([event])

    def generate_security_report(self):
        report = {}
        for event_hash, events in self.security_event_logs.items():
            report[event_hash] = [event['event_type'] for event in events]
        return report


# Test Case
node_network = ['Node1', 'Node2', 'Node3']
security_tool_parser = DecentralizedSecurityToolParser(node_network)

security_event_data = [
    {'event_type': 'Malware Detection', 'node': 'Node1', 'timestamp': '2022-01-01 12:00:00'},
    {'event_type': 'Unauthorized Access', 'node': 'Node2', 'timestamp': '2022-01-02 13:00:00'},
    {'event_type': 'DDoS Attack', 'node': 'Node3', 'timestamp': '2022-01-03 14:00:00'},
    {'event_type': 'Malware Detection', 'node': 'Node1', 'timestamp': '2022-01-04 15:00:00'},
]

security_tool_parser.parse_security_events(security_event_data)

print(security_tool_parser.generate_security_report())