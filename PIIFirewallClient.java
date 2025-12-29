package com.piifirewall;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * PII Firewall Edge API Client for Java
 * 
 * Enterprise-grade PII detection with zero AI and zero data retention.
 * Detects 152 PII types across 50+ countries in 5ms.
 * 
 * API Reference: https://rapidapi.com/image-zero-trust-security-labs/api/pii-firewall-edge
 * 
 * @version 2.4.0
 */
public class PIIFirewallClient {

    private static final String BASE_URL = "https://pii-firewall-edge.p.rapidapi.com";
    private static final String API_HOST = "pii-firewall-edge.p.rapidapi.com";
    
    private final String apiKey;
    private int connectTimeout = 10000; // 10 seconds
    private int readTimeout = 10000;    // 10 seconds

    /**
     * Create a new PII Firewall client.
     * 
     * @param apiKey Your RapidAPI key from https://rapidapi.com
     */
    public PIIFirewallClient(String apiKey) {
        if (apiKey == null || apiKey.trim().isEmpty()) {
            throw new IllegalArgumentException("API key cannot be null or empty");
        }
        this.apiKey = apiKey;
    }

    /**
     * Set connection timeout in milliseconds.
     * @param timeout Timeout in milliseconds (default: 10000)
     */
    public void setConnectTimeout(int timeout) {
        this.connectTimeout = timeout;
    }

    /**
     * Set read timeout in milliseconds.
     * @param timeout Timeout in milliseconds (default: 10000)
     */
    public void setReadTimeout(int timeout) {
        this.readTimeout = timeout;
    }

    /**
     * Redact PII using fast mode (structured PII only, 2-5ms latency).
     * Detects: emails, phones, SSN, credit cards, API keys, etc.
     * Does NOT detect: human names, addresses.
     * 
     * @param text The text to scan for PII
     * @return RedactionResult containing redacted text and detection count
     * @throws PIIFirewallException if API call fails
     */
    public RedactionResult redactFast(String text) throws PIIFirewallException {
        return redact(text, "/v1/redact/fast", "label");
    }

    /**
     * Redact PII using fast mode with mask (asterisks instead of labels).
     * 
     * @param text The text to scan for PII
     * @return RedactionResult with PII replaced by asterisks
     * @throws PIIFirewallException if API call fails
     */
    public RedactionResult redactFastMasked(String text) throws PIIFirewallException {
        return redact(text, "/v1/redact/fast", "mask");
    }

    /**
     * Redact PII using deep mode (includes names and addresses, 5-15ms latency).
     * Detects everything in fast mode PLUS human names and street addresses.
     * Uses 2000+ name gazetteer for detection without AI.
     * 
     * @param text The text to scan for PII
     * @return RedactionResult containing redacted text and detection count
     * @throws PIIFirewallException if API call fails
     */
    public RedactionResult redactDeep(String text) throws PIIFirewallException {
        return redact(text, "/v1/redact/deep", "label");
    }

    /**
     * Redact PII using deep mode with mask (asterisks instead of labels).
     * 
     * @param text The text to scan for PII
     * @return RedactionResult with PII replaced by asterisks
     * @throws PIIFirewallException if API call fails
     */
    public RedactionResult redactDeepMasked(String text) throws PIIFirewallException {
        return redact(text, "/v1/redact/deep", "mask");
    }

    private RedactionResult redact(String text, String endpoint, String mode) throws PIIFirewallException {
        // Input validation
        if (text == null) {
            throw new PIIFirewallException("Text cannot be null", 400);
        }
        if (text.trim().isEmpty()) {
            throw new PIIFirewallException("Text cannot be empty", 400);
        }

        HttpURLConnection conn = null;
        try {
            URL url = new URL(BASE_URL + endpoint);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(connectTimeout);
            conn.setReadTimeout(readTimeout);
            conn.setDoOutput(true);
            
            // Headers
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-RapidAPI-Key", apiKey);
            conn.setRequestProperty("X-RapidAPI-Host", API_HOST);
            
            // Request body
            String jsonBody = String.format("{\"text\":\"%s\",\"mode\":\"%s\"}", 
                escapeJson(text), mode);
            
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = jsonBody.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }
            
            int responseCode = conn.getResponseCode();
            
            if (responseCode == 200) {
                String response = readResponse(conn);
                return parseResponse(response);
            } else {
                String errorResponse = readErrorResponse(conn);
                throw mapHttpError(responseCode, errorResponse);
            }
            
        } catch (IOException e) {
            throw new PIIFirewallException("Network error: " + e.getMessage(), 0, e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private String readResponse(HttpURLConnection conn) throws IOException {
        StringBuilder response = new StringBuilder();
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                response.append(line);
            }
        }
        return response.toString();
    }

    private String readErrorResponse(HttpURLConnection conn) {
        try {
            StringBuilder response = new StringBuilder();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    response.append(line);
                }
            }
            return response.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private RedactionResult parseResponse(String json) throws PIIFirewallException {
        try {
            // Simple JSON parsing without external dependencies
            String redacted = extractJsonString(json, "redacted");
            int detections = extractJsonInt(json, "detections");
            String warning = extractJsonString(json, "warning");
            
            return new RedactionResult(redacted, detections, warning);
        } catch (Exception e) {
            throw new PIIFirewallException("Failed to parse API response: " + e.getMessage(), 0, e);
        }
    }

    private String extractJsonString(String json, String key) {
        String searchKey = "\"" + key + "\":\"";
        int start = json.indexOf(searchKey);
        if (start == -1) return null;
        start += searchKey.length();
        int end = json.indexOf("\"", start);
        if (end == -1) return null;
        return unescapeJson(json.substring(start, end));
    }

    private int extractJsonInt(String json, String key) {
        String searchKey = "\"" + key + "\":";
        int start = json.indexOf(searchKey);
        if (start == -1) return 0;
        start += searchKey.length();
        int end = start;
        while (end < json.length() && Character.isDigit(json.charAt(end))) {
            end++;
        }
        return Integer.parseInt(json.substring(start, end));
    }

    private String escapeJson(String text) {
        return text
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t");
    }

    private String unescapeJson(String text) {
        return text
            .replace("\\n", "\n")
            .replace("\\r", "\r")
            .replace("\\t", "\t")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\");
    }

    private PIIFirewallException mapHttpError(int statusCode, String response) {
        String errorMessage = extractJsonString(response, "error");
        if (errorMessage == null) errorMessage = "Unknown error";

        switch (statusCode) {
            case 400:
                return new PIIFirewallException("Bad Request: " + errorMessage, statusCode);
            case 401:
                return new PIIFirewallException("Unauthorized: Invalid or missing API key", statusCode);
            case 403:
                return new PIIFirewallException("Forbidden: API key does not have access", statusCode);
            case 413:
                return new PIIFirewallException("Payload Too Large: " + errorMessage, statusCode);
            case 429:
                return new PIIFirewallException("Rate Limit Exceeded: Upgrade your plan or wait", statusCode);
            case 500:
                return new PIIFirewallException("Server Error: Please try again later", statusCode);
            default:
                return new PIIFirewallException("HTTP Error " + statusCode + ": " + errorMessage, statusCode);
        }
    }

    /**
     * Result of a PII redaction operation.
     */
    public static class RedactionResult {
        private final String redactedText;
        private final int detectionCount;
        private final String warning;

        public RedactionResult(String redactedText, int detectionCount, String warning) {
            this.redactedText = redactedText;
            this.detectionCount = detectionCount;
            this.warning = warning;
        }

        /** Get the redacted text with PII replaced */
        public String getRedactedText() { return redactedText; }
        
        /** Get the number of PII items detected */
        public int getDetectionCount() { return detectionCount; }
        
        /** Get any warning message (may be null) */
        public String getWarning() { return warning; }
        
        /** Check if PII was found */
        public boolean hasPII() { return detectionCount > 0; }

        @Override
        public String toString() {
            return String.format("RedactionResult{detections=%d, redacted='%s'}", 
                detectionCount, redactedText);
        }
    }

    /**
     * Exception thrown when PII Firewall API call fails.
     */
    public static class PIIFirewallException extends Exception {
        private final int statusCode;

        public PIIFirewallException(String message, int statusCode) {
            super(message);
            this.statusCode = statusCode;
        }

        public PIIFirewallException(String message, int statusCode, Throwable cause) {
            super(message, cause);
            this.statusCode = statusCode;
        }

        /** Get HTTP status code (0 if network error) */
        public int getStatusCode() { return statusCode; }
        
        /** Check if error is retryable */
        public boolean isRetryable() {
            return statusCode == 0 || statusCode == 429 || statusCode >= 500;
        }
    }
}
