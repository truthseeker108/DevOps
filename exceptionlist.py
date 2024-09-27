import csv
from datetime import datetime

def parse_port(port_string):
    if '/' in port_string:
        protocol, port = port_string.split('/')
        return {'protocol': protocol.lower(), 'port': port}
    return {'protocol': 'any', 'port': port_string}

def read_firewall_logs(file_path):
    logs = []
    with open(file_path, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            logs.append({
                'source_ip': row[0],
                'destination_ip': row[1],
                'source_port': parse_port(row[2]),
                'destination_port': parse_port(row[3]),
                'timestamp': datetime.strptime(row[4], '%Y-%m-%d %H:%M:%S')
            })
    return logs

def read_exceptions(file_path):
    exceptions = []
    with open(file_path, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            exceptions.append({
                'source_ip': row[0],
                'destination_ip': row[1],
                'source_port': [parse_port(p.strip()) for p in row[2].split(',')],
                'destination_port': [parse_port(p.strip()) for p in row[3].split(',')],
                'expiry_date': datetime.strptime(row[4], '%Y-%m-%d')
            })
    return exceptions

def port_matches(log_port, exception_ports):
    for exc_port in exception_ports:
        if (exc_port['protocol'] == 'any' or log_port['protocol'] == exc_port['protocol']) and \
           (exc_port['port'] == 'ANY' or log_port['port'] == exc_port['port']):
            return True
    return False

def filter_logs(logs, exceptions):
    filtered_logs = []
    for log in logs:
        should_keep = True
        for exception in exceptions:
            if (
                (exception['source_ip'] == 'ANY' or log['source_ip'] == exception['source_ip']) and
                (exception['destination_ip'] == 'ANY' or log['destination_ip'] == exception['destination_ip']) and
                port_matches(log['source_port'], exception['source_port']) and
                port_matches(log['destination_port'], exception['destination_port']) and
                log['timestamp'].date() <= exception['expiry_date'].date()
            ):
                should_keep = False
                break
        if should_keep:
            filtered_logs.append(log)
    return filtered_logs

def export_filtered_logs(filtered_logs, output_file):
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        for log in filtered_logs:
            writer.writerow([
                log['source_ip'],
                log['destination_ip'],
                f"{log['source_port']['protocol']}/{log['source_port']['port']}",
                f"{log['destination_port']['protocol']}/{log['destination_port']['port']}",
                log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            ])

def main():
    firewall_log_file = 'firewall_logs.csv'
    exceptions_file = 'exceptions.csv'
    output_file = 'filtered_logs.csv'

    logs = read_firewall_logs(firewall_log_file)
    exceptions = read_exceptions(exceptions_file)
    filtered_logs = filter_logs(logs, exceptions)
    export_filtered_logs(filtered_logs, output_file)

    print(f"Szűrés befejezve. A szűrt logok exportálva: {output_file}")

if __name__ == "__main__":
    main()
