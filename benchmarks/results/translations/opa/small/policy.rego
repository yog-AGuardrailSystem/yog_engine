package yogbench

import future.keywords.in

allowed contains true if {
    data.role[input.actor] == "admin"
}

allowed contains true if {
    some team in object.get(data.member, input.actor, [])
    input.resource in object.get(data.team_resource, team, [])
}

allowed contains true if {
    data.role[input.actor] == "manager"
    input.resource in data.public
}

allowed contains true if {
    object.get(data.clearance, input.actor, -1) >= object.get(data.classification, input.resource, 1000000)
}

decision := "ALLOW" if { count(allowed) > 0 } else := "DENY"
