------------------------------- MODULE Trifecta -------------------------------
(***************************************************************************)
(* The lethal-trifecta rule of agentwall across MCP servers.               *)
(*                                                                         *)
(* One agentwall process guards each server. They share the session taint  *)
(* through marker files (internal/session), so answers from different      *)
(* servers and the agent's calls interleave in any order. A source answer  *)
(* goes through firewall.onResponse, which records taint, and only then    *)
(* does internal/proxy write it to the agent. An egress call is checked    *)
(* against the shared taint in firewall.onRequest.                         *)
(*                                                                         *)
(* NoLeak: the firewall never lets an egress call through once the agent   *)
(* has seen both untrusted and private data. TaintFirst = FALSE models the  *)
(* bug of delivering an answer before its taint is recorded; TLC must find *)
(* a leak then (TrifectaBroken.cfg), which shows the check has teeth.      *)
(***************************************************************************)
EXTENDS FiniteSets

CONSTANTS
    UntrustedSrc,   \* servers whose answers strangers can write (get_issue, fetch)
    PrivateSrc,     \* servers whose answers hold private data (read_file)
    EgressSink,     \* servers whose calls send data out (create_pull_request, fetch)
    TaintFirst      \* TRUE: taint is recorded before the answer is delivered (the real code)

Sources == UntrustedSrc \cup PrivateSrc
Labels(s) == (IF s \in UntrustedSrc THEN {"untrusted"} ELSE {})
              \cup (IF s \in PrivateSrc THEN {"private"} ELSE {})
Trifecta == {"untrusted", "private"}

VARIABLES
    taint,       \* labels in the session's marker files, shared by every process
    unrecorded,  \* answers read from a server whose taint is not in the files yet
    undelivered, \* answers read from a server, not yet written to the agent
    seen,        \* labels of everything the agent has read
    leaked       \* an egress call went out while the agent held both kinds of data

vars == <<taint, unrecorded, undelivered, seen, leaked>>

TypeOK == /\ taint \subseteq Trifecta
          /\ unrecorded \subseteq Sources
          /\ undelivered \subseteq Sources
          /\ seen \subseteq Trifecta
          /\ leaked \in BOOLEAN

Init == /\ taint = {}
        /\ unrecorded = {}
        /\ undelivered = {}
        /\ seen = {}
        /\ leaked = FALSE

\* A server answers a call (one answer per server in flight at a time).
Receive(s) == /\ s \notin unrecorded \cup undelivered
              /\ unrecorded' = unrecorded \cup {s}
              /\ undelivered' = undelivered \cup {s}
              /\ UNCHANGED <<taint, seen, leaked>>

\* onResponse writes the answer's taint to the shared files: its own step,
\* so other processes and the agent can act between it and the delivery.
Record(s) == /\ s \in unrecorded
             /\ unrecorded' = unrecorded \ {s}
             /\ taint' = taint \cup Labels(s)
             /\ UNCHANGED <<undelivered, seen, leaked>>

\* The proxy writes the answer to the agent: in the real code, only after Record.
Deliver(s) == /\ s \in undelivered
              /\ TaintFirst => s \notin unrecorded
              /\ undelivered' = undelivered \ {s}
              /\ seen' = seen \cup Labels(s)
              /\ UNCHANGED <<taint, unrecorded, leaked>>

\* The agent calls an egress tool. onRequest denies it when the shared taint holds
\* the trifecta; otherwise it goes out, carrying whatever the agent has seen.
Egress(s) == /\ s \in EgressSink
             /\ ~(Trifecta \subseteq taint)
             /\ leaked' = (leaked \/ Trifecta \subseteq seen)
             /\ UNCHANGED <<taint, unrecorded, undelivered, seen>>

Next == \/ \E s \in Sources : Receive(s) \/ Record(s) \/ Deliver(s)
        \/ \E s \in EgressSink : Egress(s)

Spec == Init /\ [][Next]_vars

NoLeak == ~leaked

\* Taint only grows and always covers what the agent has seen (the core lemma).
TaintCoversSeen == TaintFirst => seen \subseteq taint
=============================================================================
