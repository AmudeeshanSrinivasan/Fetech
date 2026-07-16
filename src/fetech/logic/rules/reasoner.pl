:- use_module(library(http/json)).
:- initialization(main, main).

main :-
    json_read_dict(current_input, Input),
    reason(Input, Output),
    json_write_dict(current_output, Output, [width(0)]),
    nl.

reason(Input, Output) :-
    Capability = Input.capability_id,
    ( Input.allowed == true, Input.available == true ->
        Eligible = true,
        Conclusion = "eligible",
        base_reasons(Input, ["capability is registered, allowed, and available"], Reasons)
    ;
        Eligible = false,
        Conclusion = "ineligible",
        denied_reasons(Input, [], DeniedReasons),
        base_reasons(Input, DeniedReasons, Reasons)
    ),
    Output = _{
        capability_id: Capability,
        conclusion: Conclusion,
        eligible: Eligible,
        reasons: Reasons
    }.

denied_reasons(Input, Initial, Reasons) :-
    ( Input.allowed == false ->
        append(Initial, ["capability is denied by the request policy"], WithPolicy)
    ;
        WithPolicy = Initial
    ),
    ( Input.available == false ->
        append(WithPolicy, ["capability implementation is unavailable"], Reasons)
    ;
        Reasons = WithPolicy
    ).

base_reasons(Input, Initial, Reasons) :-
    Dependencies = Input.dependencies,
    ( Dependencies == [] ->
        Reasons = Initial
    ;
        atomics_to_string(Dependencies, ", ", DependencyText),
        string_concat("dependencies: ", DependencyText, Message),
        append(Initial, [Message], Reasons)
    ).
