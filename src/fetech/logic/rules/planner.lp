% Fetech bounded planning constraints. Python generates all facts.

selected(Node) :- required(Node).
selected(Dependency) :- selected(Node), dependency(Node, Dependency).

:- selected(Node), unavailable(Node).
:- selected(Node), denied(Node).
:- selected(Node), not node(Node).
:- required(Node), not selected(Node).

#show selected/1.
