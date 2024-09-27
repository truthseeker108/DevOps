import csv
from datetime import datetime

def parse_port(port_string):
    if '/' in port_string:
        protocol, port = port_string.split('/')
        return {'protocol': protocol.lower(), 'port': port}
    return {'protocol': 'any', 'port': port_string}

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

def should_keep_log(log, exceptions):
    for exception in exceptions:
        if (
            (exception['source_ip'] == 'ANY' or log['source_ip'] == exception['source_ip']) and
            (exception['destination_ip'] == 'ANY' or log['destination_ip'] == exception['destination_ip']) and
            port_matches(log['source_port'], exception['source_port']) and
            port_matches(log['destination_port'], exception['destination_port']) and
            log['timestamp'].date() <= exception['expiry_date'].date()
        ):
            return False
    return True

def process_logs_in_chunks(input_file, output_file, exceptions, chunk_size=10000):
    with open(input_file, 'r') as in_file, open(output_file, 'w', newline='') as out_file:
        reader = csv.reader(in_file)
        writer = csv.writer(out_file)
        
        chunk = []
        for row in reader:
            chunk.append({
                'source_ip': row[0],
                'destination_ip': row[1],
                'source_port': parse_port(row[2]),
                'destination_port': parse_port(row[3]),
                'timestamp': datetime.strptime(row[4], '%Y-%m-%d %H:%M:%S')
            })
            
            if len(chunk) == chunk_size:
                filtered_chunk = [log for log in chunk if should_keep_log(log, exceptions)]
                for log in filtered_chunk:
                    writer.writerow([
                        log['source_ip'],
                        log['destination_ip'],
                        f"{log['source_port']['protocol']}/{log['source_port']['port']}",
                        f"{log['destination_port']['protocol']}/{log['destination_port']['port']}",
                        log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                    ])
                chunk = []
        
        # Process remaining logs
        if chunk:
            filtered_chunk = [log for log in chunk if should_keep_log(log, exceptions)]
            for log in filtered_chunk:
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

    exceptions = read_exceptions(exceptions_file)
    process_logs_in_chunks(firewall_log_file, output_file, exceptions)

    print(f"Szűrés befejezve. A szűrt logok exportálva: {output_file}")

if __name__ == "__main__":
    main()
