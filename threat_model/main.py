from threat_summarizer import summarize_threat

def cli_entry():
    print("🛡️  AI Threat Intel CLI (Type 'exit' to quit)")
    
    while True:
        try:
            threat = input("\n📝 Enter threat description or IOC: ")
            if threat.lower() in ['exit', 'quit']:
                print("👋 Exiting...")
                break
                
            if not threat.strip():
                continue

            model = input("🤖 Enter model (default: llama3.2:latest): ") or "llama3.2:latest"
            
            print("\n⏳ Analyzing...")
            result = summarize_threat(threat, model)

            print("\n--- 🔍 THREAT SUMMARY ---")
            print(f"Time: {result['timestamp']}")
            print(f"Severity: {result['severity']}")
            print(f"Input: {result['input']}\n")
            print(result['summary'])
            print("-" * 30)
            
        except KeyboardInterrupt:
            print("\n👋 Exiting...")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    cli_entry()
