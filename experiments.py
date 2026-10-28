import random
import statistics

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from simulator import run_attack, run_false_positive

TRIALS = 30
IPS_PER_SUBNET = 16
SUCCESS_THRESHOLD = 0.75
ATTACKER_SUBNETS = [1, 2, 4, 8, 16, 32]
TRADEOFF_SUBNETS = 16
SUBNET_LIMITS = [1, 2, 3, 4, 6]
SCORE_THRESHOLDS = [10, 20, 40, 80, 160, 320]

MODES = [
    ("none", "no defence"),
    ("ip", "one key per IP (CM2)"),
    ("subnet", "per-/24 cap (geth fix)"),
    ("score", "identity-churn score (ours)"),
]


def prob(values):
    return sum(1 for v in values if v >= SUCCESS_THRESHOLD) / len(values)


def mean_frac(fn):
    return statistics.mean(fn() for _ in range(TRIALS))


def experiment_attack():
    ips = [a * IPS_PER_SUBNET for a in ATTACKER_SUBNETS]
    print("\nExperiment 1: eclipse success probability vs attacker IP count")
    print(f"(attacker holds A /24 subnets x {IPS_PER_SUBNET} IPs; P[adv share >= {SUCCESS_THRESHOLD:.0%}])")
    header = f"{'IPs':>6}" + "".join(f"{m:>10}" for m, _ in MODES)
    print(header)
    series = {m: [] for m, _ in MODES}
    for a, n_ip in zip(ATTACKER_SUBNETS, ips):
        row = {}
        for m, _ in MODES:
            row[m] = prob([run_attack(a, m) for _ in range(TRIALS)])
            series[m].append(row[m])
        print(f"{n_ip:>6}" + "".join(f"{row[m]:>10.2f}" for m, _ in MODES))
    plt.figure(figsize=(6.5, 4))
    markers = ["o", "v", "s", "^"]
    for (m, label), mk in zip(MODES, markers):
        plt.plot(ips, series[m], mk + "-", label=label)
    plt.xlabel("attacker IP count")
    plt.ylabel("eclipse success probability")
    plt.title("Low-resource eclipse attack vs countermeasures")
    plt.ylim(-0.05, 1.05)
    plt.grid(True, alpha=0.3)
    plt.legend(fontsize=8)
    plt.tight_layout()
    plt.savefig("success_prob.png", dpi=120)
    plt.close()


def experiment_tradeoff():
    ip_total = TRADEOFF_SUBNETS * IPS_PER_SUBNET
    print(f"\nExperiment 2: honest false-positive rate vs attack severity "
          f"(attacker = {TRADEOFF_SUBNETS} subnets / {ip_total} IPs)")
    print("  per-/24 cap (geth fix):")
    sub_fp, sub_sev = [], []
    for L in SUBNET_LIMITS:
        fp = mean_frac(lambda L=L: run_false_positive("subnet", subnet_limit=L))
        sev = mean_frac(lambda L=L: run_attack(TRADEOFF_SUBNETS, "subnet", subnet_limit=L))
        sub_fp.append(fp)
        sub_sev.append(sev)
        print(f"    L={L}  FP={fp:.3f}  adv_share={sev:.3f}")
    print("  identity-churn score (ours):")
    sc_fp, sc_sev = [], []
    for T in SCORE_THRESHOLDS:
        fp = mean_frac(lambda T=T: run_false_positive("score", threshold=T))
        sev = mean_frac(lambda T=T: run_attack(TRADEOFF_SUBNETS, "score", threshold=T))
        sc_fp.append(fp)
        sc_sev.append(sev)
        print(f"    threshold={T}  FP={fp:.3f}  adv_share={sev:.3f}")
    plt.figure(figsize=(6.5, 4))
    plt.plot(sub_sev, sub_fp, "s-", label="per-/24 cap (geth fix)")
    plt.plot(sc_sev, sc_fp, "^-", label="identity-churn score (ours)")
    plt.xlabel("attack severity (mean adversary table share)")
    plt.ylabel("honest false-positive rate")
    plt.title("Security vs false positives (lower-left is better)")
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig("defence_tradeoff.png", dpi=120)
    plt.close()


if __name__ == "__main__":
    random.seed(1)
    experiment_attack()
    experiment_tradeoff()
    print("\nSaved: success_prob.png, defence_tradeoff.png")
