import numpy as np
import random
import collections
# import matplotlib.pyplot as plt

fail_rate = 0.33
num_nodes = 10000
lvl0_nodes = 200
lvl1_nodes_per_group = 200
num_groups = int(np.ceil(num_nodes/200))

stop_condition = 32


max_runs = 96


def run_shred(max_runs=max_runs, sufficient_percent_seen=1/3):
    max_count = 0
    observed = np.zeros(num_nodes)
    node_indexes = np.arange(num_nodes)
    for i in range(max_runs):

        # to account for 33% of the time the lvl0 reciever is malicious

        # if random.random() <= 1/3:
        #     continue
        # NOTE: I had to turn this off becuase max shreds was getting exceeded

        # simple shuffleing steps:
        # 1 shuffle the deck
        # 2 pick the first lvl0_nodes and your lvl0
        # 3 hack off the next indexes by lvl1_nodes_per_group amount
        # TODO: do I have to worry about the case when this isn't mod 0?
        np.random.shuffle(node_indexes)

        lvl0 = node_indexes[:lvl0_nodes]

        lvl1_groups = np.array(
            [node_indexes[lvl0_nodes + lvl1_nodes_per_group * i:
                          lvl0_nodes + lvl1_nodes_per_group * (i+1)]
             for i in range(num_groups)]
            )

        # lvl0 reciever transmitted, then lvl0 all see it
        observed[lvl0] += 1

        # this tracks the indexes of the groups in lvl1 that were transmitted to
        seen = np.random.choice(lvl1_groups, num_groups*2//3, replace=False)

        # count all those who were transmitted to in this shred
        for s in seen:
            observed[s] += 1

        # this just pythonically counts how many packets are recieved across
        # all shreds
        counts_of_nodes_total_observed = collections.Counter(observed)
        s = sorted(counts_of_nodes_total_observed.most_common(),
                   key=lambda x: x[0])

        # this basically runs this sim until a sufficient amount of nodes have
        # seen enough packets. ie the "stop condition"
        cum = 0
        si = 0

        sufficient_seen = sum(counts_of_nodes_total_observed.values()) \
            * sufficient_percent_seen

        while cum < sufficient_seen:
            cum += s[si][1]
            si += 1

        # The logic here is that what we care about is the max packets anyone
        # has seen in a case that's less than the required amount of the network
        # has seen enough packets. That way we can be assured if
        # we see packets above that maximum, then we know the network is in
        # a good state

        if s[si-1][0] > stop_condition:
            return max_count, i, s
        else:
            # Realistically all we need to do is check the last shred before we
            # hit the stop condition, but checking it time is just not as efficient
            max_count = max(
                max(counts_of_nodes_total_observed.elements()), max_count)

        # EXTREME FAILURE CASE
        if i == max_runs - 1:
            raise Exception("Max shreds exceeded!")


# Run a bunch of sims
maxes = []
for i in range(10000):
    maxes.append(run_shred())

# look at the max of those sims to see the worst case
# index 0 is the max_counts
# index 1 is the number of shreds
# index 2 is shows all the seen packet counts that each node saw

max(maxes, key=lambda x: x[0])


# This gives a rough distribution
collect = collections.Counter([m[0] for m in maxes])
print(sorted(collect.items(), key=lambda x: x[0]))

# TODO: any failure cases where the number of shreds exceeded 96?
