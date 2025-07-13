from threat_summarizer import summarize_threat

def cli_entry():
    threat = input("Enter threat description or IOC: ")
    model = input("Enter model (llama2, gpt-j, mistral): ") or "llama2"
    
    result = summarize_threat(threat, model)

    print("\n--- THREAT SUMMARY ---")
    print(f"Time: {result['timestamp']}")
    print(f"Severity: {result['severity']}")
    print(f"Input: {result['input']}\n")
    print(result['summary'])

if __name__ == "__main__":
    cli_entry()
