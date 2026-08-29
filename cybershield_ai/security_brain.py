from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict

class Verdict(str, Enum):
    CLEAN="CLEAN"; SUSPICIOUS="SUSPICIOUS"; HIGH="HIGH"; CRITICAL="CRITICAL"; HUMAN_REVIEW="HUMAN_REVIEW"

@dataclass(frozen=True)
class Evidence:
    source:str; signal:str; score:float; details:str=""; confidence:float=0.7; independent:bool=True; counter:bool=False

@dataclass
class Decision:
    verdict:Verdict; risk_score:int; confidence:float; reasons:List[str]=field(default_factory=list); safe_actions:List[str]=field(default_factory=list); escalate:bool=False; attack_chain:List[str]=field(default_factory=list); counter_evidence:List[str]=field(default_factory=list); coverage:float=0.0

class SecurityBrain:
    """Evidence-fusion decision layer. It is deterministic, auditable and fail-closed."""
    CHAIN={"execution":"Execution","persistence":"Persistence","network":"Network","credential":"Credential access","evasion":"Evasion","filesystem":"Filesystem","process":"Process behavior","phishing":"Phishing"}
    def analyze(self,evidence:List[Evidence])->Decision:
        if not evidence:
            return Decision(Verdict.HUMAN_REVIEW,0,0.0,["Yetarli dalil mavjud emas."],["MONITOR","HUMAN_REVIEW"],True,coverage=0.0)
        pos=[e for e in evidence if not e.counter]; neg=[e for e in evidence if e.counter]
        # strongest independent evidence dominates; duplicate signals have diminishing weight
        seen=set(); weighted=[]
        for e in sorted(pos,key=lambda x:x.score,reverse=True):
            key=(e.source,e.signal.lower())
            if key in seen: continue
            seen.add(key); weighted.append(max(0,min(100,e.score))*max(.25,min(1,e.confidence)))
        strongest=max(weighted,default=0); corroboration=sum(weighted[1:4])*0.22
        risk=max(0,min(100,round(strongest*0.72+corroboration)))
        # counter-evidence reduces confidence/risk but never erases a critical independent signal
        counter_penalty=min(24,sum(max(0,min(100,e.score))*0.12 for e in neg))
        if risk < 85: risk=max(0,round(risk-counter_penalty))
        sources={e.source for e in pos if e.independent}; coverage=min(1.0,len(sources)/6)
        confidence=min(.995,.34+.11*min(len(sources),5)+.055*min(len(weighted),5)+.08*coverage)
        chain=[]
        text=' '.join((e.signal+' '+e.details).lower() for e in pos)
        for key,label in self.CHAIN.items():
            if key in text: chain.append(label)
        if len(chain)>=3: risk=min(100,risk+8); confidence=min(.995,confidence+.04)
        reasons=[f"{e.source}: {e.signal}" for e in sorted(pos,key=lambda x:x.score,reverse=True) if e.score>=45][:8]
        counters=[f"{e.source}: {e.signal}" for e in neg[:5]]
        if risk>=88: verdict=Verdict.CRITICAL
        elif risk>=68: verdict=Verdict.HIGH
        elif risk>=42: verdict=Verdict.SUSPICIOUS
        else: verdict=Verdict.CLEAN
        escalate=(verdict in {Verdict.CRITICAL,Verdict.HIGH} and confidence<.78) or confidence<.58
        actions=["PRESERVE_EVIDENCE","AUDIT_LOG"]
        if verdict==Verdict.CLEAN: actions += ["MONITOR"]
        elif verdict==Verdict.SUSPICIOUS: actions += ["CONTAIN","MONITOR"]
        else: actions += ["CONTAIN","QUARANTINE","VERIFY"]
        if escalate: actions += ["HUMAN_REVIEW"]
        return Decision(verdict,risk,confidence,reasons,actions,escalate,chain,counters,coverage)
