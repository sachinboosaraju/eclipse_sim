import heapq
import random

from kademlia import RoutingTable, Peer, random_id


class Sim:
    def __init__(self):
        self.t = 0.0
        self.q = []
        self.seq = 0

    def at(self, t, fn):
        heapq.heappush(self.q, (t, self.seq, fn))
        self.seq += 1

    def run(self, t_end):
        while self.q and self.q[0][0] <= t_end:
            t, _, fn = heapq.heappop(self.q)
            self.t = t
            fn()


def make_honest(n, n_cloud_subnets, cloud_fraction):
    nodes = {}
    for _ in range(n):
        nid = random_id()
        if random.random() < cloud_fraction:
            subnet = ("cloud", random.randrange(n_cloud_subnets))
        else:
            subnet = ("host", nid & 0xFFFFFF)
        nodes[nid] = Peer(nid, ("ip", nid), subnet, adversary=False)
    return nodes


def _table(victim, mode, k, subnet_limit, threshold):
    if mode == "ip":
        return RoutingTable(victim, k=k, mode="ip", ip_table=1)
    if mode == "subnet":
        return RoutingTable(victim, k=k, mode="subnet",
                            subnet_bucket=subnet_limit, subnet_table=5 * subnet_limit)
    if mode == "ipsubnet":
        return RoutingTable(victim, k=k, mode="ipsubnet", ip_table=1,
                            subnet_bucket=subnet_limit, subnet_table=5 * subnet_limit)
    if mode == "score":
        return RoutingTable(victim, k=k, mode="score", threshold=threshold)
    return RoutingTable(victim, k=k, mode="none")


def run_attack(attacker_subnets, mode, ips_per_subnet=16, subnet_limit=2, threshold=100,
               n_honest=800, n_cloud_subnets=12, cloud_fraction=0.3, churn_rate=0.02,
               discover_rate=4.0, attack_rate=40.0, attack_start=50.0,
               t_end=200.0, k=16):
    victim = random_id()
    honest = make_honest(n_honest, n_cloud_subnets, cloud_fraction)
    online = {nid: True for nid in honest}
    hlist = list(honest.values())
    table = _table(victim, mode, k, subnet_limit, threshold)

    def is_online(peer):
        return True if peer.adversary else online[peer.id]

    sim = Sim()

    def discover():
        p = random.choice(hlist)
        if online[p.id]:
            table.add(p, is_online, sim.t)
        sim.at(sim.t + random.expovariate(discover_rate), discover)

    def churn(p):
        online[p.id] = not online[p.id]
        sim.at(sim.t + random.expovariate(churn_rate), lambda: churn(p))

    def attack():
        s = random.randrange(attacker_subnets)
        ip = random.randrange(ips_per_subnet)
        table.add(Peer(random_id(), ("adv", s, ip), ("adv", s), adversary=True), is_online, sim.t)
        if sim.t < t_end:
            sim.at(sim.t + random.expovariate(attack_rate), attack)

    sim.at(0.0, discover)
    for p in hlist:
        sim.at(random.expovariate(churn_rate), lambda p=p: churn(p))
    sim.at(attack_start, attack)
    sim.run(t_end)

    adv, hon = table.composition()
    return adv / (adv + hon) if adv + hon else 0.0


def run_false_positive(mode, subnet_limit=2, threshold=100, n_honest=800,
                       n_cloud_subnets=12, cloud_fraction=0.3, churn_rate=0.02,
                       discover_rate=4.0, t_end=200.0, k=16):
    victim = random_id()
    honest = make_honest(n_honest, n_cloud_subnets, cloud_fraction)
    online = {nid: True for nid in honest}
    hlist = list(honest.values())
    table = _table(victim, mode, k, subnet_limit, threshold)

    def is_online(peer):
        return online[peer.id]

    stats = {"rejected": 0, "attempts": 0}
    sim = Sim()

    def discover():
        p = random.choice(hlist)
        if online[p.id]:
            r = table.add(p, is_online, sim.t)
            if r in ("added", "evicted", "rejected_room"):
                stats["attempts"] += 1
                if r == "rejected_room":
                    stats["rejected"] += 1
        sim.at(sim.t + random.expovariate(discover_rate), discover)

    def churn(p):
        online[p.id] = not online[p.id]
        sim.at(sim.t + random.expovariate(churn_rate), lambda: churn(p))

    sim.at(0.0, discover)
    for p in hlist:
        sim.at(random.expovariate(churn_rate), lambda p=p: churn(p))
    sim.run(t_end)

    return stats["rejected"] / stats["attempts"] if stats["attempts"] else 0.0
