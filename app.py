import os
import modal

def download_model():
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    AutoTokenizer.from_pretrained("AventIQ-AI/Bert_Email_Spam_Detaction")
    AutoModelForSequenceClassification.from_pretrained("AventIQ-AI/Bert_Email_Spam_Detaction")

image = (
    modal.Image.debian_slim()
    .pip_install("transformers", "torch", "limits")
    .run_function(download_model) # Bakes your working model weights into the cloud image
)

app = modal.App("enterprise-email-security", image=image)

@app.cls(
    concurrency_limit=5,        # Protects your credits from scaling infinitely
    allow_concurrent_inputs=20   # Multi-threading handling
)
class SecurityScanner:
    @modal.enter()
    def load_model(self):
        import torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        from limits import strategies, storage
        
        self.torch = torch
        self.tokenizer = AutoTokenizer.from_pretrained("AventIQ-AI/Bert_Email_Spam_Detaction")
        self.model = AutoModelForSequenceClassification.from_pretrained("AventIQ-AI/Bert_Email_Spam_Detaction")
        self.model.eval()

        self.storage = storage.MemoryStorage()
        self.limiter = strategies.MovingWindowRateLimiter(self.storage)

    @modal.web_endpoint(method="POST", secrets=[modal.Secret.from_name("security-api-key")])
    def scan(self, data: dict, request: modal.Request):
        from limits import parse
        
        # Enforce your custom secret key gate
        client_id = request.headers.get("X-Client-ID", "anonymous_user")
        auth_header = request.headers.get("Authorization", "")
        if auth_header != f"Bearer {os.environ['API_TOKEN']}":
            return {"error": "Unauthorized access denied"}, 401

        # Enforce enterprise Tier 2 limits
        burst_rule = parse("10 per 5 seconds")
        sustained_rule = parse("60 per minute")

        if not self.limiter.hit(burst_rule, client_id) or not self.limiter.hit(sustained_rule, client_id):
            return {"error": "Too Many Requests", "message": "Rate limits exceeded."}, 429

        email_text = data.get("email_text", "")
        if not email_text:
            return {"error": "Missing 'email_text' payload"}, 400

        inputs = self.tokenizer(email_text, padding=True, truncation=True, return_tensors="pt")
        with self.torch.no_grad():
            outputs = self.model(**inputs)
            
        prediction = self.torch.argmax(outputs.logits, dim=-1).item()
        is_malicious = (prediction == 1)
        
        return {
            "is_malicious": is_malicious,
            "action": "BLOCK" if is_malicious else "ALLOW"
        }
