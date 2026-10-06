from sanitizer import sanitize_pcap
from detector import analyze

if __name__ == "__main__":
    sanitize_pcap("input.pcap", "output.pcap") # debug for now, later will be implemented to the website using Flask
    result = analyze("output.pcap")
    print(result)
