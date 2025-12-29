# PII Firewall Edge - Java SDK

Enterprise-grade PII detection for Java applications. Zero AI. Zero Logs. 5ms latency.

## Quick Start

### 1. Get Your API Key

Sign up at [RapidAPI](https://rapidapi.com/image-zero-trust-security-labs/api/pii-firewall-edge) to get your free API key (500 requests/month).

### 2. Add to Your Project

Copy `PIIFirewallClient.java` to your project's source directory.

### 3. Basic Usage

```java
import com.piifirewall.PIIFirewallClient;
import com.piifirewall.PIIFirewallClient.RedactionResult;
import com.piifirewall.PIIFirewallClient.PIIFirewallException;

public class Example {
    public static void main(String[] args) {
        // Initialize client
        PIIFirewallClient client = new PIIFirewallClient("YOUR_RAPIDAPI_KEY");
        
        try {
            // Fast mode (emails, phones, SSNs, credit cards, etc.)
            RedactionResult result = client.redactFast(
                "Contact john@company.com at 555-123-4567. SSN: 123-45-6789"
            );
            
            System.out.println("Redacted: " + result.getRedactedText());
            // Output: Contact [EMAIL] at [PHONE_US]. SSN: [SSN]
            
            System.out.println("Detections: " + result.getDetectionCount());
            // Output: 3
            
        } catch (PIIFirewallException e) {
            System.err.println("Error: " + e.getMessage());
            System.err.println("Status Code: " + e.getStatusCode());
        }
    }
}
```


## Integration with LLMs

Sanitize user input before sending to ChatGPT/Claude:

```java
public String processWithAI(String userMessage) throws PIIFirewallException {
    PIIFirewallClient piiClient = new PIIFirewallClient(System.getenv("RAPIDAPI_KEY"));
    
    // Step 1: Redact PII before sending to LLM
    RedactionResult sanitized = piiClient.redactFast(userMessage);
    
    // Step 2: Send sanitized text to your LLM
    String aiResponse = yourOpenAIClient.chat(sanitized.getRedactedText());
    
    return aiResponse;
}
```

## Error Handling

```java
try {
    RedactionResult result = client.redactFast(userInput);
    // Success
} catch (PIIFirewallException e) {
    switch (e.getStatusCode()) {
        case 400:
            System.err.println("Invalid input: " + e.getMessage());
            break;
        case 401:
            System.err.println("Invalid API key - check your RapidAPI key");
            break;
        case 413:
            System.err.println("Text too large - max 20KB (Basic) or 100KB (Pro+)");
            break;
        case 429:
            System.err.println("Rate limit exceeded - upgrade plan or wait");
            break;
        default:
            if (e.isRetryable()) {
                System.err.println("Temporary error - retry in a few seconds");
            }
    }
}
```

## Pricing

| Plan | Price | Requests/Month |
|------|-------|----------------|
| Basic | $0 | 500 |
| Pro | $5 | 5,000 |
| Ultra | $10 | 20,000 |
| Mega | $25 | 75,000 |

## PII Types Detected

152 types across 50+ countries including:

- **Contact**: Email, Phone (US/UK/IN/Intl)
- **Government**: SSN, Passport, Driver's License, Tax IDs
- **Financial**: Credit Card, IBAN, SWIFT, Crypto addresses
- **Healthcare**: NPI, DEA, Medicare, MRN
- **Developer**: AWS, GitHub, Stripe, OpenAI, Slack API keys

## Support

- **Documentation**: [RapidAPI Docs](https://rapidapi.com/image-zero-trust-security-labs/api/pii-firewall-edge)
- **SDK Examples**: [GitHub](https://github.com/myProjectsRavi/pii-firewall-edge-api-examples)
- **Email**: [Contact Support](mailto:piifirewalledge@gmail.com)

## License

MIT License
