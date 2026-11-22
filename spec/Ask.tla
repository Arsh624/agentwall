--------------------------------- MODULE Ask ---------------------------------
(***************************************************************************)
(* agentwall's "ask" flow over MCP elicitation (internal/proxy, v0.3).      *)
(*                                                                         *)
(* For a call the policy marks "ask", the proxy sends the agent an         *)
(* elicitation/create question and keeps the call in an "asking" map. The  *)
(* user's answer, a 5-minute timeout and the agent cancelling the call all *)
(* race to end the question; whichever takes it out of the map first wins *)
(* (one mutex), and a later answer is dropped.                             *)
(*                                                                         *)
(* Checked: a call reaches the server only after the user accepted it      *)
(* (OnlyApproved), the agent never gets two replies to one call            *)
(* (OneReply), a cancelled call is never forwarded (CancelHolds), and every *)
(* question ends (AllEnd). ClearOnTimeout = FALSE models forgetting to      *)
(* remove the question when the timeout denies the call; TLC must find     *)
(* that a late "accept" then forwards a call the agent was told is denied. *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    Reqs,           \* calls the policy sends to "ask"
    ClearOnTimeout  \* TRUE in the real code

Final == {"none", "done"}

VARIABLES
    asking,     \* calls with an open question (the proxy's map)
    question,   \* per call: "none", "out" (with the user), "accept"/"decline" (answer on its way), "done"
    accepted,   \* calls whose accept the proxy acted on
    upstream,   \* calls forwarded to the server
    replies,    \* per call: replies the agent got (a blocked error, or the server's answer)
    cancelled   \* calls the agent cancelled

vars == <<asking, question, accepted, upstream, replies, cancelled>>

TypeOK == /\ asking \subseteq Reqs
          /\ question \in [Reqs -> {"none", "out", "accept", "decline", "done"}]
          /\ accepted \subseteq Reqs /\ upstream \subseteq Reqs /\ cancelled \subseteq Reqs
          /\ replies \in [Reqs -> Nat]

Init == /\ asking = {}
        /\ question = [r \in Reqs |-> "none"]
        /\ accepted = {} /\ upstream = {} /\ cancelled = {}
        /\ replies = [r \in Reqs |-> 0]

\* The policy says ask: the proxy sends elicitation/create and remembers the call.
Ask(r) == /\ question[r] = "none"
          /\ asking' = asking \cup {r}
          /\ question' = [question EXCEPT ![r] = "out"]
          /\ UNCHANGED <<accepted, upstream, replies, cancelled>>

\* The user answers in the agent; the answer travels back (it may arrive late).
Answer(r, a) == /\ question[r] = "out"
                /\ question' = [question EXCEPT ![r] = a]
                /\ UNCHANGED <<asking, accepted, upstream, replies, cancelled>>

\* The proxy reads the answer. Only a call still in the map is acted on.
Handle(r) == /\ question[r] \in {"accept", "decline"}
             /\ question' = [question EXCEPT ![r] = "done"]
             /\ IF r \in asking
                  THEN /\ asking' = asking \ {r}
                       /\ IF question[r] = "accept"
                            THEN /\ accepted' = accepted \cup {r}
                                 /\ upstream' = upstream \cup {r}   \* its answer reaches the agent later
                                 /\ replies' = [replies EXCEPT ![r] = @ + 1]
                            ELSE /\ replies' = [replies EXCEPT ![r] = @ + 1]   \* blocked error
                                 /\ UNCHANGED <<accepted, upstream>>
                  ELSE UNCHANGED <<asking, accepted, upstream, replies>>   \* late answer: dropped
             /\ UNCHANGED cancelled

\* No answer in time: the call is denied.
Timeout(r) == /\ r \in asking
              /\ asking' = IF ClearOnTimeout THEN asking \ {r} ELSE asking
              /\ replies' = [replies EXCEPT ![r] = @ + 1]
              /\ UNCHANGED <<question, accepted, upstream, cancelled>>

\* The agent gives up on the call (notifications/cancelled): no reply is owed.
Cancel(r) == /\ r \in asking
             /\ asking' = asking \ {r}
             /\ cancelled' = cancelled \cup {r}
             /\ UNCHANGED <<question, accepted, upstream, replies>>

\* Every question asked and every answer read: a normal end, not a deadlock.
\* TLC still reports any other state with no next step.
Finished == /\ \A r \in Reqs : question[r] = "done"
            /\ UNCHANGED vars

Next == \/ \E r \in Reqs : \/ Ask(r) \/ Handle(r) \/ Timeout(r) \/ Cancel(r)
                           \/ \E a \in {"accept", "decline"} : Answer(r, a)
        \/ Finished

Spec == Init /\ [][Next]_vars /\ \A r \in Reqs : WF_vars(Timeout(r))

OnlyApproved == upstream \subseteq accepted
OneReply     == \A r \in Reqs : replies[r] <= 1
CancelHolds  == upstream \cap cancelled = {}
AllEnd       == \A r \in Reqs : (r \in asking) ~> (r \notin asking)

\* Keeps the broken variant's state space finite (its timeout can fire again and again).
Bounded == \A r \in Reqs : replies[r] <= 2
=============================================================================
