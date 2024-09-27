import csv
import re
from datetime import datetime

def is_valid_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(part) <= 255 for part in ip.split('.'))

def is_valid_port(port):
    if port == 'ANY':
        return True
    pattern = r'^(tcp|udp)/\d+$'
    if not re.match(pattern, port):
        return False
    protocol, port_num = port.split('/')
    return 0 <= int(port_num) <= 65535

def validate_port_list(ports):
    return all(is_valid_port(port.strip()) for port in ports.split(','))

def parse_port(port_string):
    if '/' in port_string:
        protocol, port = port_string.split('/')
        return {'protocol': protocol.lower(), 'port': port}
    return {'protocol': 'any', 'port': port_string}

def read_firewall_logs(file_path):
    logs = []
    with open(file_path, 'r') as file:
        reader = csv.reader(file)
        for row_num, row in enumerate(reader, start=1):
            if len(row) != 5:
                raise ValueError(f"Hibás sor formátum a {row_num}. sorban: {row}")
            if not is_valid_ip(row[0]) or not is_valid_ip(row[1]):
                raise ValueError(f"Érvénytelen IP cím a {row_num}. sorban: {row}")
            if not is_valid_port(row[2]) or not is_valid_port(row[3]):
                raise ValueError(f"Érvénytelen port a {row_num}. sorban: {row}")
            try:
                timestamp = datetime.strptime(row[4], '%Y-%m-%d %H:%M:%S')
            except ValueError:
                raise ValueError(f"Érvénytelen időbélyeg a {row_num}. sorban: {row[4]}")
            
            logs.append({
                'source_ip': row[0],
                'destination_ip': row[1],
                'source_port': parse_port(row[2]),
                'destination_port': parse_port(row[3]),
                'timestamp': timestamp
            })
    return logs

def read_exceptions(file_path):
    exceptions = []
    with open(file_path, 'r') as file:
        reader = csv.reader(file)
        for row_num, row in enumerate(reader, start=1):
            if len(row) != 5:
                raise ValueError(f"Hibás sor formátum a {row_num}. sorban: {row}")
            if row[0] != 'ANY' and not is_valid_ip(row[0]):
                raise ValueError(f"Érvénytelen forrás IP cím a {row_num}. sorban: {row[0]}")
            if row[1] != 'ANY' and not is_valid_ip(row[1]):
                raise ValueError(f"Érvénytelen cél IP cím a {row_num}. sorban: {row[1]}")
            if not validate_port_list(row[2]):
                raise ValueError(f"Érvénytelen forrás port lista a {row_num}. sorban: {row[2]}")
            if not validate_port_list(row[3]):
                raise ValueError(f"Érvénytelen cél port lista a {row_num}. sorban: {row[3]}")
            try:
                expiry_date = datetime.strptime(row[4], '%Y-%m-%d')
            except ValueError:
                raise ValueError(f"Érvénytelen lejárati dátum a {row_num}. sorban: {row[4]}")
            
            exceptions.append({
                'source_ip': row[0],
                'destination_ip': row[1],
                'source_port': [parse_port(p.strip()) for p in row[2].split(',')],
                'destination_port': [parse_port(p.strip()) for p in row[3].split(',')],
                'expiry_date': expiry_date
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

    try:
        logs = read_firewall_logs(firewall_log_file)
        exceptions = read_exceptions(exceptions_file)
        filtered_logs = filter_logs(logs, exceptions)
        export_filtered_logs(filtered_logs, output_file)
        print(f"Szűrés befejezve. A szűrt logok exportálva: {output_file}")
    except ValueError as e:
        print(f"Hiba történt a fájlok feldolgozása során: {e}")
    except FileNotFoundError as e:
        print(f"A megadott fájl nem található: {e}")
    except Exception as e:
        print(f"Váratlan hiba történt: {e}")

if __name__ == "__main__":
    main()
