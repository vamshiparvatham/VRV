import re
import csv
from collections import Counter, defaultdict

# Function to parse the log file and extract necessary data
def parse_log_file(filename):
    ip_request_count = Counter()
    endpoint_access_count = Counter()
    failed_login_attempts = defaultdict(int)
    
    with open(filename, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip_address = ip_match.group(1)
                ip_request_count[ip_address] += 1

            # Extract endpoint
            endpoint_match = re.search(r'"(?:GET|POST)\s(\S+)', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_access_count[endpoint] += 1

            # Detect failed login attempts
            if '401' in line or 'Invalid credentials' in line:
                if ip_match:
                    failed_login_attempts[ip_address] += 1

    return ip_request_count, endpoint_access_count, failed_login_attempts

# Function to detect suspicious activity based on failed login attempts
def detect_suspicious_activity(failed_logins, threshold=10):
    print("Failed login attempts per IP:")
    for ip, count in failed_logins.items():
        print(f"{ip}: {count}")
    return {ip: count for ip, count in failed_logins.items() if count > threshold}


# Function to write results to a CSV file
def write_results_to_csv(ip_requests, top_endpoint, suspicious_activity, output_filename):
    with open(output_filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])  # Blank row for separation
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([top_endpoint[0], top_endpoint[1]])

        # Write suspicious activity
        writer.writerow([])  # Blank row for separation
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

# Main function
def main():
    log_file = "sample.log"
    output_file = "log_analysis_results.csv"

    # Parse log file
    ip_requests, endpoint_accesses, failed_logins = parse_log_file(log_file)

    # Identify the most accessed endpoint
    top_endpoint = endpoint_accesses.most_common(1)[0] if endpoint_accesses else ("None", 0)

    # Detect suspicious activity
    suspicious_activity = detect_suspicious_activity(failed_logins, threshold=3)

    # Display results
    print("Requests per IP Address:")
    print("IP Address\t\tRequest Count")
    for ip, count in ip_requests.most_common():
        print(f"{ip}\t{count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{top_endpoint[0]} (Accessed {top_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address\t\tFailed Login Attempts")
    for ip, count in suspicious_activity.items():
        print(f"{ip}\t{count}")

    # Write results to CSV
    write_results_to_csv(ip_requests, top_endpoint, suspicious_activity, output_file)
    print(f"\nResults written to {output_file}")

if __name__ == "__main__":
    main()
