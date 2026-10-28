import random

ID_BITS = 256


def random_id():
    return random.getrandbits(ID_BITS)


def logdist(a, b):
    return (a ^ b).bit_length()


class Peer:
    __slots__ = ("id", "ip", "subnet", "adversary", "t_added")

    def __init__(self, id, ip, subnet, adversary=False):
        self.id = id
        self.ip = ip
        self.subnet = subnet
        self.adversary = adversary
        self.t_added = 0.0


class RoutingTable:
    def __init__(self, owner, k=16, mode="none", ip_bucket=None, ip_table=None,
                 subnet_bucket=None, subnet_table=None, threshold=100):
        self.owner = owner
        self.k = k
        self.mode = mode
        self.ip_bucket = ip_bucket
        self.ip_table = ip_table
        self.subnet_bucket = subnet_bucket
        self.subnet_table = subnet_table
        self.threshold = threshold
        self.buckets = {}
        self.ip_count = {}
        self.subnet_count = {}
        self.seen = {}

    def _insert(self, bucket, peer, now):
        peer.t_added = now
        bucket.append(peer)
        self.ip_count[peer.ip] = self.ip_count.get(peer.ip, 0) + 1
        self.subnet_count[peer.subnet] = self.subnet_count.get(peer.subnet, 0) + 1

    def _remove(self, bucket, peer):
        bucket.remove(peer)
        self.ip_count[peer.ip] -= 1
        self.subnet_count[peer.subnet] -= 1

    def _limited(self, bucket, peer):
        if self.ip_table is not None and self.ip_count.get(peer.ip, 0) >= self.ip_table:
            return True
        if self.subnet_table is not None and self.subnet_count.get(peer.subnet, 0) >= self.subnet_table:
            return True
        if self.ip_bucket is not None and sum(1 for p in bucket if p.ip == peer.ip) >= self.ip_bucket:
            return True
        if self.subnet_bucket is not None and sum(1 for p in bucket if p.subnet == peer.subnet) >= self.subnet_bucket:
            return True
        return False

    def _ids(self, subnet):
        return len(self.seen.get(subnet, ()))

    def add(self, peer, is_online, now=0.0):
        idx = logdist(self.owner, peer.id)
        if idx == 0:
            return "self"
        bucket = self.buckets.setdefault(idx, [])
        for i, p in enumerate(bucket):
            if p.id == peer.id:
                bucket.append(bucket.pop(i))
                return "present"
        full = len(bucket) >= self.k

        if self.mode == "score":
            self.seen.setdefault(peer.subnet, set()).add(peer.id)
            flagged = self._ids(peer.subnet) > self.threshold
            if not full:
                if flagged:
                    return "rejected_room"
                self._insert(bucket, peer, now)
                return "added"
            if flagged:
                return "rejected_full"
            victim = max(bucket, key=lambda p: (0 if is_online(p) else 1,
                                                self._ids(p.subnet), -p.t_added))
            if not is_online(victim) or self._ids(victim.subnet) > self._ids(peer.subnet):
                self._remove(bucket, victim)
                self._insert(bucket, peer, now)
                return "evicted"
            return "rejected_full"

        if self.mode != "none" and self._limited(bucket, peer):
            return "rejected_full" if full else "rejected_room"
        if not full:
            self._insert(bucket, peer, now)
            return "added"
        inc = bucket[0]
        if is_online(inc):
            bucket.append(bucket.pop(0))
            return "rejected_full"
        self._remove(bucket, inc)
        self._insert(bucket, peer, now)
        return "evicted"

    def entries(self):
        for bucket in self.buckets.values():
            for p in bucket:
                yield p

    def composition(self):
        adv = hon = 0
        for p in self.entries():
            if p.adversary:
                adv += 1
            else:
                hon += 1
        return adv, hon
