import re
import argparse
from email import message_from_string
import dns.resolver
import requests
from ipwhois import IPWhois
from datetime import datetime, timezone
import os
import mimetypes

def parse_email_header(raw_email):
    """Parse email headers and extract key fields."""
    email_message = message_from_string(raw_email)
    email_data = {
        "From": email_message.get("From"),
        "To": email_message.get("To"),
        "Subject": email_message.get("Subject"),
        "Date": email_message.get("Date"),
        "Received": email_message.get_all("Received")
    }
    return email_data

def extract_ips(received_headers):
    """Extract IP addresses from Received headers."""
    ip_pattern = re.compile(r"\d+\.\d+\.\d+\.\d+")
    ips = []
    for header in received_headers:
        ips.extend(ip_pattern.findall(header))
    return ips

def check_spf(domain):
    """Check the SPF record for the sender's domain."""
    try:
        answers = dns.resolver.resolve(f"{domain}", "TXT")
        for rdata in answers:
            if "v=spf1" in str(rdata):
                return str(rdata)
        return "No SPF record found"
    except Exception as e:
        return f"Error checking SPF: {e}"

def geolocate_ip(ip):
    """Get geolocation information for an IP address."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        if response.status_code == 200:
            data = response.json()
            return {
                "Country": data.get("country"),
                "Region": data.get("regionName"),
                "City": data.get("city"),
                "ISP": data.get("isp")
            }
        return {"Error": "Unable to fetch geolocation data"}
    except Exception as e:
        return {"Error": str(e)}

def suspicious_pattern_detection(ips):
    """Detect suspicious patterns in the extracted IPs."""
    suspicious_ips = []
    for ip in ips:
        try:
            obj = IPWhois(ip)
            whois_info = obj.lookup_rdap()
            if "bogon" in whois_info.get("asn_description", "").lower():
                suspicious_ips.append(ip)
        except Exception:
            pass
    return suspicious_ips

def blacklist_check(ip):
    """Check if an IP is blacklisted."""
    try:
        response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}")
        if response.status_code == 200:
            data = response.json()
            return data.get("data", {}).get("abuseConfidenceScore", "No data")
        return "Error checking blacklist status"
    except Exception as e:
        return f"Error: {e}"

def check_dkim(domain):
    """Check the DKIM record for the domain."""
    try:
        answers = dns.resolver.resolve(f"_domainkey.{domain}", "TXT")
        for rdata in answers:
            return str(rdata)
        return "No DKIM record found"
    except Exception as e:
        return f"Error checking DKIM: {e}"

def check_dmarc(domain):
    """Check the DMARC policy for the domain."""
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            return str(rdata)
        return "No DMARC policy found"
    except Exception as e:
        return f"Error checking DMARC: {e}"

def validate_timestamp(date_header):
    """Validate the timestamp in the email header."""
    try:
        email_time = datetime.strptime(date_header, "%a, %d %b %Y %H:%M:%S %z")
        current_time = datetime.now(timezone.utc)
        if email_time > current_time:
            return "Timestamp is in the future! Possible spoofing."
        return "Timestamp is valid."
    except Exception as e:
        return f"Error validating timestamp: {e}"

def extract_attachment_metadata(file_path):
    """Extract metadata from email attachments."""
    try:
        attachments = []
        with open(file_path, "rb") as f:
            raw_email = f.read()
            email_message = message_from_string(raw_email.decode("utf-8", errors="ignore"))
            for part in email_message.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                if part.get("Content-Disposition") is None:
                    continue
                filename = part.get_filename()
                if filename:
                    attachments.append({
                        "Filename": filename,
                        "Content-Type": part.get_content_type(),
                        "Size (bytes)": len(part.get_payload(decode=True))
                    })
        return attachments if attachments else "No attachments found."
    except Exception as e:
        return f"Error extracting attachment metadata: {e}"

def analyze_email(file_path, features):
    """Analyze the email header from a file."""
    try:
        with open(file_path, "r") as f:
            raw_email = f.read()
        email_data = parse_email_header(raw_email)

        if "header" in features:
            print("=== Email Header Information ===")
            print(f"From: {email_data['From']}")
            print(f"To: {email_data['To']}")
            print(f"Subject: {email_data['Subject']}")
            print(f"Date: {email_data['Date']}")

        if "ips" in features:
            print("\n=== Extracted IPs ===")
            if email_data["Received"]:
                ips = extract_ips(email_data["Received"])
                for ip in ips:
                    print(ip)

        if "spf" in features and email_data['From']:
            domain = email_data['From'].split('@')[-1]
            print("\n=== SPF Check ===")
            print(f"SPF Record: {check_spf(domain)}")

        if "geolocation" in features and email_data["Received"]:
            ips = extract_ips(email_data["Received"])
            print("\n=== Geolocation Information ===")
            for ip in ips:
                geolocation = geolocate_ip(ip)
                print(f"IP: {ip}, Location: {geolocation}")

        if "suspicious" in features and email_data["Received"]:
            ips = extract_ips(email_data["Received"])
            print("\n=== Suspicious Pattern Detection ===")
            suspicious_ips = suspicious_pattern_detection(ips)
            if suspicious_ips:
                print("Suspicious IPs detected:")
                for ip in suspicious_ips:
                    print(ip)
            else:
                print("No suspicious IPs detected.")

        if "blacklist" in features and email_data["Received"]:
            ips = extract_ips(email_data["Received"])
            print("\n=== Blacklist Check ===")
            for ip in ips:
                print(f"IP: {ip}, Blacklist Status: {blacklist_check(ip)}")

        if "dkim" in features and email_data['From']:
            domain = email_data['From'].split('@')[-1]
            print("\n=== DKIM Check ===")
            print(f"DKIM Record: {check_dkim(domain)}")

        if "dmarc" in features and email_data['From']:
            domain = email_data['From'].split('@')[-1]
            print("\n=== DMARC Check ===")
            print(f"DMARC Policy: {check_dmarc(domain)}")

        if "timestamp" in features and email_data['Date']:
            print("\n=== Timestamp Validation ===")
            print(validate_timestamp(email_data['Date']))

        if "attachments" in features:
            print("\n=== Attachment Metadata ===")
            print(extract_attachment_metadata(file_path))

    except FileNotFoundError:
        print("Error: File not found.")
    except Exception as e:
        print(f"Error analyzing email: {e}")

def main():
    """Main function to handle CLI arguments."""
    parser = argparse.ArgumentParser(description="Email Header Analyzer Tool with Forensics Features")
    parser.add_argument("file", help="Path to the email file to analyze")
    parser.add_argument(
        "--features",
        nargs="+",
        choices=[
            "header", "ips", "spf", "geolocation", "suspicious", "blacklist",
            "dkim", "dmarc", "timestamp", "attachments"
        ],
        default=["header", "ips", "spf", "geolocation", "suspicious"],
        help="Features to enable for analysis"
    )
    args = parser.parse_args()

    analyze_email(args.file, args.features)

if __name__ == "__main__":
    main()

