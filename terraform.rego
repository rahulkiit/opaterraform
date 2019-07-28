package terraform.analysis

import input as tfplan

########################
# Parameters for Policy
########################

# acceptable score for automated authorization
blast_radius = 10

# weights assigned for each operation on each resource-type
weights = {
    "aws_autoscaling_group": {"delete": 100, "create": 10, "modify": 1},
    "aws_instance": {"delete": 10, "create": 1, "modify": 1}
}

# Consider exactly these resource types in calculations
resource_types = {"aws_autoscaling_group", "aws_instance", "aws_iam", "aws_launch_configuration"}

#########
# Policy
#########

# Authorization holds if score for the plan is acceptable and no changes are made to IAM
default authz = false
authz {
    score < blast_radius
    not touches_iam
}

# Compute the score for a Terraform plan as the weighted sum of deletions, creations, modifications
score = s {
    all := [ x |
            crud := weights[resource_type];
            del := crud["delete"] * num_deletes[resource_type];
            new := crud["create"] * num_creates[resource_type];
            mod := crud["modify"] * num_modifies[resource_type];
            x := del + new + mod
    ]
    s := sum(all)
}

# Whether there is any change to IAM
touches_iam {
    all := instance_names["aws_iam"]
    count(all) > 0
}

####################
# Terraform Library
####################

# list of all resources of a given type
instance_names[resource_type] = all {
    resource_types[resource_type]
    all := [name |
        tfplan[name] = _
        startswith(name, resource_type)
    ]
}

# number of deletions of resources of a given type
num_deletes[resource_type] = num {
    resource_types[resource_type]
    all := instance_names[resource_type]
    deletions := [name | name := all[_]; obj := tfplan[name]; obj["change"]["actions"][_] == "delete"]
    num := count(deletions)
}

# number of creations of resources of a given type
num_creates[resource_type] = num {
    resource_types[resource_type]
    all := instance_names[resource_type]
    creates := [name | all[_] = name; obj := tfplan[name]; obj["change"]["actions"][_] == "create"]
    num := count(creates)
}

# number of modifications to resources of a given type
num_modifies[resource_type] = num {
    resource_types[resource_type]
    all := instance_names[resource_type]
    modifies := [name | name := all[_]; obj := tfplan[name]; obj["change"]["actions"][_] == "update"]
    num := count(modifies)
}