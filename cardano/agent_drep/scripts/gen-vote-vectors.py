"""Ed25519 test vectors for validators/agent_drep.test.ak.

Signs the exact bytes of lib/alma/vote.ak `message` with a throwaway key
(seed 0x11..11). Run: python3 -I scripts/gen-vote-vectors.py  (needs pynacl).
"""
import hashlib, json
from nacl.signing import SigningKey
DOMAIN=b"alma-drep-vote/1"
def msg(drep, txid, idx, vote, seq, exp):
    return DOMAIN+drep+txid+idx.to_bytes(2,'big')+bytes([vote])+seq.to_bytes(8,'big')+exp.to_bytes(8,'big')
human = SigningKey(bytes.fromhex("11"*32)); other = SigningKey(bytes.fromhex("22"*32))
hv = bytes(human.verify_key); ov=bytes(other.verify_key)
def vkh(vk): return hashlib.blake2b(vk, digest_size=28).hexdigest()
drep=bytes.fromhex("aa"*28); txid=bytes.fromhex("bb"*32)
vec={"human_vkey":hv.hex(),"human_vkh":vkh(hv),"other_vkey":ov.hex(),"drep":drep.hex(),"gov_tx":txid.hex()}
# vote codes No=0 Yes=1 Abstain=2
cases={"yes_seq0_exp1000":(0,1,0,1000),"yes_seq1_exp1000":(0,1,1,1000),"no_seq0_exp1000":(0,0,0,1000)}
for k,(idx,vote,seq,exp) in cases.items():
    m=msg(drep,txid,idx,vote,seq,exp)
    vec["sig_"+k]=human.sign(m).signature.hex()
    vec["msg_"+k]=m.hex()
vec["sig_other_yes_seq0_exp1000"]=other.sign(msg(drep,txid,0,1,0,1000)).signature.hex()
print(json.dumps(vec,indent=1))
