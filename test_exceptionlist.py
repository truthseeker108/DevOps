import unittest
from datetime import datetime
from firewall_log_filter import read_firewall_logs, read_exceptions, filter_logs, export_filtered_logs, parse_port
import tempfile
import os
import csv

class TestFirewallLogFilter(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        for file in os.listdir(self.temp_dir):
            os.remove(os.path.join(self.temp_dir, file))
        os.rmdir(self.temp_dir)

    def test_parse_port(self):
        self.assertEqual(parse_port('tcp/443'), {'protocol': 'tcp', 'port': '443'})
        self.assertEqual(parse_port('udp/9000'), {'protocol': 'udp', 'port': '9000'})
        self.assertEqual(parse_port('8080'), {'protocol': 'any', 'port': '8080'})

    def test_read_firewall_logs(self):
        log_file = os.path.join(self.temp_dir, 'test_logs.csv')
        with open(log_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['192.168.1.1', '10.0.0.1', 'tcp/80', 'tcp/443', '2023-01-01 12:00:00'])
        
        logs = read_firewall_logs(log_file)
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]['source_ip'], '192.168.1.1')
        self.assertEqual(logs[0]['source_port'], {'protocol': 'tcp', 'port': '80'})
        self.assertEqual(logs[0]['destination_port'], {'protocol': 'tcp', 'port': '443'})
        self.assertEqual(logs[0]['timestamp'], datetime(2023, 1, 1, 12, 0, 0))

    def test_read_exceptions(self):
        exceptions_file = os.path.join(self.temp_dir, 'test_exceptions.csv')
        with open(exceptions_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['192.168.1.1', 'ANY', 'tcp/80, udp/53', 'tcp/443', '2023-12-31'])
        
        exceptions = read_exceptions(exceptions_file)
        self.assertEqual(len(exceptions), 1)
        self.assertEqual(exceptions[0]['source_ip'], '192.168.1.1')
        self.assertEqual(exceptions[0]['destination_ip'], 'ANY')
        self.assertEqual(exceptions[0]['source_port'], [{'protocol': 'tcp', 'port': '80'}, {'protocol': 'udp', 'port': '53'}])
        self.assertEqual(exceptions[0]['destination_port'], [{'protocol': 'tcp', 'port': '443'}])
        self.assertEqual(exceptions[0]['expiry_date'], datetime(2023, 12, 31))

    def test_filter_logs_with_protocol_ports(self):
        logs = [
            {'source_ip': '192.168.1.1', 'destination_ip': '10.0.0.1', 'source_port': {'protocol': 'tcp', 'port': '80'}, 'destination_port': {'protocol': 'tcp', 'port': '443'}, 'timestamp': datetime(2023, 1, 1, 12, 0, 0)},
            {'source_ip': '192.168.1.2', 'destination_ip': '10.0.0.2', 'source_port': {'protocol': 'udp', 'port': '53'}, 'destination_port': {'protocol': 'udp', 'port': '53'}, 'timestamp': datetime(2023, 1, 2, 12, 0, 0)},
            {'source_ip': '192.168.1.3', 'destination_ip': '10.0.0.3', 'source_port': {'protocol': 'tcp', 'port': '22'}, 'destination_port': {'protocol': 'tcp', 'port': '22'}, 'timestamp': datetime(2023, 1, 3, 12, 0, 0)}
        ]
        exceptions = [
            {'source_ip': '192.168.1.1', 'destination_ip': 'ANY', 'source_port': [{'protocol': 'tcp', 'port': '80'}], 'destination_port': [{'protocol': 'tcp', 'port': '443'}], 'expiry_date': datetime(2023, 12, 31)},
            {'source_ip': 'ANY', 'destination_ip': '10.0.0.2', 'source_port': [{'protocol': 'any', 'port': 'ANY'}], 'destination_port': [{'protocol': 'udp', 'port': '53'}], 'expiry_date': datetime(2023, 12, 31)}
        ]

        filtered_logs = filter_logs(logs, exceptions)
        self.assertEqual(len(filtered_logs), 1)
        self.assertEqual(filtered_logs[0]['source_ip'], '192.168.1.3')

    def test_export_filtered_logs(self):
        filtered_logs = [
            {'source_ip': '192.168.1.3', 'destination_ip': '10.0.0.3', 'source_port': {'protocol': 'tcp', 'port': '22'}, 'destination_port': {'protocol': 'tcp', 'port': '22'}, 'timestamp': datetime(2023, 1, 3, 12, 0, 0)}
        ]
        output_file = os.path.join(self.temp_dir, 'test_output.csv')
        export_filtered_logs(filtered_logs, output_file)

        with open(output_file, 'r') as f:
            reader = csv.reader(f)
            rows = list(reader)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0], ['192.168.1.3', '10.0.0.3', 'tcp/22', 'tcp/22', '2023-01-03 12:00:00'])

if __name__ == '__main__':
    unittest.main()
