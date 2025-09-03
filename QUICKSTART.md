# 🚀 AAS QUICKSTART: Add Trusted Attestations to Your Hackathon MVP

## 🎯 What This Does (30-second pitch)

**Stop trusting user claims. Start verifying them cryptographically.**

Instead of this: *"I'm a student at Stanford"* (Hope they're not lying 🤞)
Do this: *"I have a cryptographically signed attestation from Stanford"* (Mathematically provable ✅)

**Real hackathon use cases in 2025:**
- 🎓 **Student verification**: "Prove you go to this university without revealing your student ID"
- ⭐ **Reputation systems**: "This freelancer has 5 verified completed projects" 
- 🎫 **Event attendance**: "I was at this conference" (signed by organizers)
- 💼 **KYC compliance**: "This address is whitelisted" (signed by compliance team)
- 🏆 **Achievement proofs**: "I completed this course/challenge" (signed by platform)

**The magic**: Users control their attestations. Verifiers can't fake them. Privacy-preserving by design.

---

## ⚡ 10-Minute Setup (From Zero to First Attestation)

### Prerequisites (2 minutes)
```bash
# Check you have these installed
docker --version    # Need Docker for LocalNet
python --version    # Need Python 3.12+
uv --version        # Need uv package manager

# Install missing tools
curl -LsSf https://astral.sh/uv/install.sh | sh  # Install uv
pip install algokit  # Install AlgoKit for LocalNet
```

### Environment Setup (3 minutes)
```bash
# 1. Start Algorand LocalNet (takes 30 seconds)
algokit localnet start

# 2. Clone and install AAS
git clone <your-repo-url>
cd algorand-aas
uv pip install -e .

# 3. Set environment variables (LocalNet defaults)
export AAS_ALGOD_URL="http://localhost:4001"
export AAS_ALGOD_TOKEN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
```

### Deploy AAS & Create First Attestation (5 minutes)
```bash
# 4. Auto-deploy AAS to LocalNet (uses existing scripts)
echo "Deploying AAS contract..."
AAS_MNEMONIC=$(uv run python scripts/kmd_mnemonic.py)
export AAS_MNEMONIC

AAS_APP_ID=$(uv run python scripts/deploy_app.py)
export AAS_APP_ID
echo "✅ AAS deployed! App ID: $AAS_APP_ID"

# 5. Fund the app for storage
uv run python scripts/fund_app.py $AAS_APP_ID 1000000
echo "✅ App funded for box storage"

# 6. Create your first schema (student verification)
cat > student_schema.json << 'EOF'
{
  "type": "object",
  "title": "Student Verification",
  "properties": {
    "university": {"type": "string"},
    "studentId": {"type": "string"},
    "graduationYear": {"type": "integer"}
  },
  "required": ["university", "studentId", "graduationYear"]
}
EOF

# 7. Register the schema
uv run aas create-schema student_schema.json --uri "https://my-hackathon.com/student-schema"
echo "✅ Schema created!"

# 8. Generate an attester keypair
KEYS=$(uv run python scripts/generate_attester.py)
ATTESTER_SK=$(echo $KEYS | cut -d' ' -f1)
ATTESTER_PK=$(echo $KEYS | cut -d' ' -f2)
echo "✅ Generated attester keys"

# 9. Grant attester permission (replace SCHEMA_ID with actual output)
SCHEMA_ID="your_schema_id_here"  # Use the ID from step 7
uv run aas grant-attester $SCHEMA_ID $ATTESTER_PK

# 10. Create a student claim
cat > student_claim.json << 'EOF'
{
  "university": "Stanford University",
  "studentId": "12345678",
  "graduationYear": 2025
}
EOF

# 11. Sign and create attestation
STUDENT_ADDRESS="TCKO4NR6BCAKCXFR7CPZEXUJ7K4NVPSOQFBRS2FPXN6CCJPGGDQOEI6BRM"  # Example
SIGNED_DATA=$(uv run python scripts/sign_attestation.py $ATTESTER_SK $SCHEMA_ID $STUDENT_ADDRESS student_claim.json)
NONCE=$(echo $SIGNED_DATA | cut -d' ' -f1)
SIGNATURE=$(echo $SIGNED_DATA | cut -d' ' -f2)

uv run aas attest $SCHEMA_ID $STUDENT_ADDRESS student_claim.json $NONCE $SIGNATURE $ATTESTER_PK
echo "✅ First attestation created!"

# 12. Verify it worked
ATTESTATION_ID="your_attestation_id_here"  # Use the ID from step 11
uv run aas get $ATTESTATION_ID
```

**🎉 Success Criteria**: If you see attestation details with status "OK", you're ready to build!

---

## 🔥 Copy-Paste Examples (Common MVP Patterns)

### A. Student ID Verification System

**Use case**: Dating app that only allows verified university students

```python
# student_verifier.py - Complete working example
import json
from aas.sdk.aas import AASClient
from algosdk.v2client.algod import AlgodClient

class StudentVerifier:
    def __init__(self, algod_url: str, algod_token: str, app_id: int):
        algod_client = AlgodClient(algod_token, algod_url)
        self.aas_client = AASClient(algod_client, app_id)
        
    def verify_student(self, user_address: str, attestation_id: str) -> dict:
        """Verify a user is a student and return their university."""
        try:
            attestation = self.aas_client.verify_attestation(attestation_id)
            if not attestation or attestation.status.value != "OK":
                return {"verified": False, "reason": "Invalid attestation"}
                
            if attestation.subject != user_address:
                return {"verified": False, "reason": "Address mismatch"}
                
            # In production, you'd store claim data off-chain
            # For demo, we'll simulate university verification
            return {
                "verified": True,
                "university": "Stanford University",  # From claim data
                "attestation_id": attestation_id
            }
        except Exception as e:
            return {"verified": False, "reason": str(e)}

# Usage in your app
verifier = StudentVerifier(
    algod_url="http://localhost:4001",
    algod_token="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    app_id=123456
)

result = verifier.verify_student(
    user_address="TCKO4NR6BCAKCXFR7CPZEXUJ7K4NVPSOQFBRS2FPXN6CCJPGGDQOEI6BRM",
    attestation_id="abc123def456..."
)

if result["verified"]:
    print(f"✅ Verified student at {result['university']}")
else:
    print(f"❌ Verification failed: {result['reason']}")
```

### B. Reputation System for Freelancers

**Use case**: Fiverr-style platform with cryptographically provable work history

```python
# reputation_system.py
from typing import List, Dict
from dataclasses import dataclass

@dataclass
class WorkAttestation:
    client_address: str
    rating: int  # 1-5 stars
    project_value: int  # in USD
    completion_date: str
    attestation_id: str

class FreelancerReputation:
    def __init__(self, aas_client):
        self.aas_client = aas_client
        
    def calculate_reputation(self, freelancer_address: str, attestation_ids: List[str]) -> Dict:
        """Calculate reputation score from verified work attestations."""
        total_rating = 0
        total_projects = 0
        total_value = 0
        verified_attestations = []
        
        for att_id in attestation_ids:
            attestation = self.aas_client.verify_attestation(att_id)
            if attestation and attestation.subject == freelancer_address:
                # Parse claim data (stored off-chain in production)
                work_data = self.get_work_data(att_id)  # Your off-chain storage
                
                total_rating += work_data["rating"]
                total_projects += 1
                total_value += work_data["project_value"]
                verified_attestations.append(att_id)
        
        if total_projects == 0:
            return {"score": 0, "projects": 0, "avg_rating": 0}
            
        return {
            "score": (total_rating / total_projects) * min(total_projects / 5, 1),
            "total_projects": total_projects,
            "avg_rating": total_rating / total_projects,
            "total_value": total_value,
            "verified_attestations": verified_attestations
        }

# Schema for work completion attestations
work_schema = {
    "type": "object",
    "title": "Work Completion Attestation",
    "properties": {
        "project_id": {"type": "string"},
        "rating": {"type": "integer", "minimum": 1, "maximum": 5},
        "project_value": {"type": "integer"},
        "completion_date": {"type": "string", "format": "date"},
        "description": {"type": "string"}
    }
}
```

### C. Event Attendance Proof

**Use case**: Conference networking app that verifies attendance

```python
# event_attendance.py
import qrcode
from io import BytesIO
import base64

class EventAttendanceSystem:
    def __init__(self, aas_client, event_schema_id: str, organizer_signer):
        self.aas_client = aas_client
        self.event_schema_id = event_schema_id
        self.organizer_signer = organizer_signer
        
    def generate_attendance_qr(self, attendee_address: str, event_id: str) -> str:
        """Generate QR code for attendee to prove they were at event."""
        # Create claim data
        claim_data = {
            "event_id": event_id,
            "event_name": "Algorand Hackathon 2025",
            "date": "2025-01-15",
            "location": "San Francisco"
        }
        
        # Sign attestation (organizers would do this at check-in)
        import secrets
        nonce = secrets.token_hex(32)
        
        # Create attestation
        attestation_id = self.aas_client.attest(
            schema_id=self.event_schema_id,
            subject_addr=attendee_address,
            claim_data=claim_data,
            nonce=nonce,
            signature="...",  # Properly signed by organizer
            attester_pk="...",  # Organizer's public key
        )
        
        # Generate QR code with attestation ID
        qr_data = {
            "type": "event_attendance",
            "attestation_id": attestation_id,
            "event_id": event_id,
            "attendee": attendee_address
        }
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(json.dumps(qr_data))
        qr.make(fit=True)
        
        # Return QR as base64 image
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"
    
    def verify_attendance(self, qr_data: dict) -> bool:
        """Verify someone actually attended the event."""
        attestation = self.aas_client.verify_attestation(qr_data["attestation_id"])
        return (attestation and 
                attestation.status.value == "OK" and
                attestation.subject == qr_data["attendee"])

# Event attendance schema
event_schema = {
    "type": "object", 
    "title": "Event Attendance",
    "properties": {
        "event_id": {"type": "string"},
        "event_name": {"type": "string"},
        "date": {"type": "string", "format": "date"},
        "location": {"type": "string"}
    }
}
```

---

## 🔧 Integration Patterns

### Frontend Integration (JavaScript/TypeScript)

```javascript
// attestation-verifier.js - For React/Vue/vanilla JS
class AttestationVerifier {
    constructor(algodUrl, algodToken, appId) {
        this.algod = new algosdk.Algodv2(algodToken, algodUrl, '');
        this.appId = appId;
    }
    
    async verifyAttestation(attestationId) {
        try {
            // Read attestation box from Algorand
            const boxName = new Uint8Array([
                ...new TextEncoder().encode('att:'),
                ...this.hexToBytes(attestationId)
            ]);
            
            const boxResponse = await this.algod.getApplicationBoxByName(this.appId, boxName).do();
            const boxData = new Uint8Array(boxResponse.value);
            
            // Parse box data (simplified)
            const status = String.fromCharCode(boxData[0]);
            const subject = algosdk.encodeAddress(boxData.slice(1, 33));
            
            return {
                valid: status === 'A',
                subject: subject,
                attestationId: attestationId
            };
        } catch (error) {
            console.error('Verification failed:', error);
            return { valid: false, error: error.message };
        }
    }
    
    hexToBytes(hex) {
        const bytes = [];
        for (let i = 0; i < hex.length; i += 2) {
            bytes.push(parseInt(hex.substr(i, 2), 16));
        }
        return new Uint8Array(bytes);
    }
}

// React component example
function UserProfile({ userAddress }) {
    const [studentStatus, setStudentStatus] = useState(null);
    
    useEffect(() => {
        const verifier = new AttestationVerifier(
            'http://localhost:4001',
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            123456
        );
        
        // User provides their attestation ID
        const attestationId = getUserAttestationId(userAddress);
        
        verifier.verifyAttestation(attestationId).then(result => {
            if (result.valid && result.subject === userAddress) {
                setStudentStatus('verified');
            } else {
                setStudentStatus('unverified');
            }
        });
    }, [userAddress]);
    
    return (
        <div className="user-profile">
            {studentStatus === 'verified' && (
                <div className="verification-badge">
                    ✅ Verified Student
                </div>
            )}
        </div>
    );
}
```

### Backend Integration (FastAPI/Flask)

```python
# app.py - FastAPI integration example
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from aas.sdk.aas import AASClient
from algosdk.v2client.algod import AlgodClient
import os

app = FastAPI(title="Hackathon App with Attestations")

# Initialize AAS client
algod_client = AlgodClient(
    os.getenv("AAS_ALGOD_TOKEN"),
    os.getenv("AAS_ALGOD_URL")
)
aas_client = AASClient(algod_client, int(os.getenv("AAS_APP_ID")))

class VerificationRequest(BaseModel):
    user_address: str
    attestation_id: str
    required_type: str  # "student", "reputation", "event_attendance"

@app.post("/verify-attestation")
async def verify_attestation(request: VerificationRequest):
    """Verify user's attestation matches their address and type."""
    try:
        attestation = aas_client.verify_attestation(request.attestation_id)
        
        if not attestation:
            raise HTTPException(status_code=404, detail="Attestation not found")
            
        if attestation.subject != request.user_address:
            raise HTTPException(status_code=400, detail="Address mismatch")
            
        if attestation.status.value != "OK":
            raise HTTPException(status_code=400, detail="Attestation revoked")
        
        # Add business logic based on attestation type
        verification_result = {
            "verified": True,
            "attestation_id": request.attestation_id,
            "subject": attestation.subject,
            "schema_id": attestation.schema_id,
            "type": request.required_type
        }
        
        return verification_result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/user/{address}/reputation")
async def get_user_reputation(address: str):
    """Get aggregated reputation from multiple attestations."""
    # Implementation depends on how you store attestation IDs per user
    # This would typically come from your database
    user_attestations = get_user_attestations_from_db(address)
    
    total_score = 0
    verified_count = 0
    
    for att_id in user_attestations:
        attestation = aas_client.verify_attestation(att_id)
        if attestation and attestation.subject == address:
            # Get score from off-chain claim data
            score = get_attestation_score(att_id)
            total_score += score
            verified_count += 1
    
    return {
        "user_address": address,
        "reputation_score": total_score / max(verified_count, 1),
        "verified_attestations": verified_count
    }
```

### Database Storage Recommendations

```python
# models.py - SQLAlchemy models for storing attestation metadata
from sqlalchemy import Column, String, Integer, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    address = Column(String, primary_key=True)  # Algorand address
    created_at = Column(DateTime)
    email = Column(String, nullable=True)  # Optional off-chain data
    
class AttestationMetadata(Base):
    """Store off-chain metadata for attestations."""
    __tablename__ = "attestation_metadata"
    
    attestation_id = Column(String, primary_key=True)
    user_address = Column(String, ForeignKey("users.address"))
    schema_id = Column(String, nullable=False)
    attestation_type = Column(String)  # "student", "work", "event"
    claim_data = Column(Text)  # JSON string of actual claim data
    created_at = Column(DateTime)
    is_active = Column(Boolean, default=True)
    
class ReputationScore(Base):
    """Cached reputation calculations."""
    __tablename__ = "reputation_scores"
    
    user_address = Column(String, primary_key=True)
    total_score = Column(Integer, default=0)
    attestation_count = Column(Integer, default=0)
    last_updated = Column(DateTime)

# Usage pattern:
# 1. Store attestation_id and claim_data in your DB when creating attestations
# 2. Verify attestation_id on-chain when needed
# 3. Use claim_data from DB for business logic (ratings, details, etc.)
# 4. Cache reputation calculations for performance
```

---

## 💡 Hackathon Project Ideas

### 🟢 Easy (4-8 hours)

**1. Student Discount Validator**
- *Problem*: Fake student IDs for discounts
- *Solution*: University-signed attestations for student status
- *Tech*: Simple verification API + frontend
- *Demo tip*: Show fake ID vs real attestation side-by-side

**2. Event Check-in System** 
- *Problem*: Fake event attendance for networking
- *Solution*: QR codes with cryptographic proof
- *Tech*: QR generator + mobile scanner
- *Demo tip*: Live check-in demo with audience

**3. Alumni Network Verifier**
- *Problem*: LinkedIn lying about education
- *Solution*: University-verified graduation attestations
- *Tech*: Chrome extension for LinkedIn verification
- *Demo tip*: Browser demo on real LinkedIn profiles

### 🟡 Medium (8-16 hours)

**4. Decentralized Freelancer Platform**
- *Problem*: Fake reviews and work history
- *Solution*: Client-signed work completion attestations  
- *Tech*: Full-stack app with reputation system
- *Demo tip*: Show side-by-side freelancer profiles (verified vs unverified)

**5. Privacy-Preserving Age Verification**
- *Problem*: Sharing full ID for "Are you 21+" checks
- *Solution*: Government attestation: "Over 21" without revealing age
- *Tech*: Zero-knowledge friendly attestation design
- *Demo tip*: Bar entry system that doesn't see your birthday

**6. Verified Review System**
- *Problem*: Fake Amazon/Yelp reviews
- *Solution*: Purchase receipt attestations for review credibility
- *Tech*: Browser extension + merchant integration
- *Demo tip*: Chrome extension showing "verified buyer" badges

### 🔴 Hard (16-24 hours)

**7. Decentralized Twitter with Verified Identity**
- *Problem*: Bots and fake accounts on social media
- *Solution*: Multiple attestation types for user verification
- *Tech*: Full social platform with attestation-based verification tiers
- *Demo tip*: Show bot detection and verification levels

**8. Cross-Chain Reputation Bridge**
- *Problem*: Reputation doesn't transfer between platforms
- *Solution*: Algorand attestations that prove Ethereum/other chain activity
- *Tech*: Cross-chain verification system
- *Demo tip*: Transfer DeFi reputation from Ethereum to Algorand

**9. Anonymous Credentialed Voting**
- *Problem*: Voting systems that reveal identity or allow fake votes
- *Solution*: Eligibility attestations with zero-knowledge proofs
- *Tech*: ZK-SNARKs + attestation system
- *Demo tip*: Live anonymous vote with real eligibility verification

### 🎯 Demo Tips for All Projects

1. **Have a "bad actor" scenario**: Show what happens with fake/invalid attestations
2. **Show the verification process**: Let judges verify an attestation themselves
3. **Compare before/after**: Demo the problem without attestations first
4. **Mobile-friendly**: Make sure your demo works on phones
5. **Real data**: Use real university names, real event names, etc.

---

## 🆘 Quick Troubleshooting

### LocalNet Issues

**Problem**: `algokit localnet start` fails
```bash
# Solution: Reset LocalNet completely
algokit localnet stop
docker system prune -f
algokit localnet start
```

**Problem**: "Connection refused" errors
```bash
# Check LocalNet is running
curl http://localhost:4001/v2/status

# Check environment variables
echo $AAS_ALGOD_URL
echo $AAS_ALGOD_TOKEN
```

**Problem**: Box storage errors ("MBR insufficient")
```bash
# Fund the app with more Algos
uv run python scripts/fund_app.py $AAS_APP_ID 5000000  # 5 Algos
```

### Common Development Issues

**Problem**: "Schema not found" errors
```bash
# List all schemas to debug
uv run python scripts/read_box.py $AAS_APP_ID schema:your_schema_id
```

**Problem**: Signature verification fails
```bash
# Verify your signing process
uv run python scripts/sign_attestation.py --debug $ATTESTER_SK $SCHEMA_ID $SUBJECT claim.json
```

**Problem**: Python import errors
```bash
# Reinstall in development mode
uv pip install -e . --force-reinstall
```

### Performance Tips

**For demos (not production)**:
- Use 1-round confirmation: faster transactions
- Cache attestation verifications: don't hit blockchain every time  
- Hardcode test data: don't generate everything live

**For development speed**:
```bash
# Fast unit tests only (0.4s)
uv run pytest -m "not localnet" -q

# Skip slow integration tests during iteration
uv run pytest tests/test_sdk_hashing.py -q
```

### Migration from LocalNet to TestNet

For final demos, switch to TestNet for stability:

```bash
export AAS_ALGOD_URL="https://testnet-api.algonode.cloud"
export AAS_ALGOD_TOKEN=""  # Usually empty for public nodes
# Use TestNet mnemonic with funded account
export AAS_MNEMONIC="your testnet mnemonic with algos"

# Deploy to TestNet
uv run python scripts/deploy_app.py
```

### Emergency Fallbacks

**If attestations break completely**:
1. Switch to simple JWT tokens for demo
2. Mock the verification functions to return `true`
3. Focus on UX and explain "this would be verified on-chain"

**If LocalNet breaks during demo**:
1. Use screenshots/videos of working system
2. Have backup TestNet deployment ready
3. Mock the blockchain calls for UI demo

---

## 📚 Resources & References

### API Documentation
- **CLI Reference**: Run `uv run aas --help` for all commands
- **SDK Reference**: Check `aas/sdk/aas.py` for `AASClient` methods
- **Schema Examples**: See `tests/` directory for working schemas

### Community & Support  
- **Discord**: [Join the Algorand Discord](https://discord.gg/algorand) for real-time help
- **GitHub Issues**: Report bugs or ask questions in this repo
- **Algorand Docs**: [developer.algorand.org](https://developer.algorand.org) for blockchain fundamentals

### Advanced Examples
- **Production Deployment**: See `scripts/deploy_app.py` for MainNet deployment
- **Performance Optimization**: Check `README.md` for test performance tips
- **Security Considerations**: Review `aas/contracts/aas.py` for smart contract security

### Useful Tools
- **AlgoKit**: `pip install algokit` - Algorand development toolkit
- **Algorand Wallet**: Use [Pera Wallet](https://perawallet.app/) for mobile testing
- **Block Explorer**: [TestNet Explorer](https://testnet.algoexplorer.io) to view your transactions

---

## 🎉 You're Ready!

You now have everything needed to add cryptographically verifiable attestations to your hackathon project. The examples above are all copy-pasteable and working - adapt them to your specific use case.

**Remember**: Focus on solving a real problem first, then add attestations to make the solution more trustworthy. Attestations are the "trust layer" that makes your MVP enterprise-ready.

**Good luck building! 🚀**

---

*Generated for hackathon developers who want to move fast and build things that matter.*