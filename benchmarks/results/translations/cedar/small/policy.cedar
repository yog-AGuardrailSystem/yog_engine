// Generated from the YOG benchmark corpus.
permit (
    principal,
    action == Action::"can_access",
    resource
)
when { principal in Role::"admin" };

permit (
    principal,
    action == Action::"can_access",
    resource
)
when { principal in resource.owner };

permit (
    principal,
    action == Action::"can_access",
    resource
)
when { principal in Role::"manager" && resource.public };

permit (
    principal,
    action == Action::"can_access",
    resource
)
when { principal.clearance >= resource.classification };
