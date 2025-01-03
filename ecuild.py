import math
import ipaddress
from scapy.all import rdpcap, IP
from collections import defaultdict
from statistics import median
import random
import matplotlib.pyplot as plt
import numpy as np

LARGE_PRIME = int(179424691) # used for hash of ExtendedCountSketch
win_id = 1 # used to refresh sketch, do not change

WIN_SIZE = 2 ** 14 # observation window size
width = 1280 # width of the sketch
depth = 4  # depth of the sketch
smoothing_coefficient = 20 * 2 ** -8 # used to calculate EWMAs and EWMMDs
sensitivity_coefficient = 3 # used to check anomaly
mitigation_threshold = 96 # used to classify packets

src_list = []
dst_list = []

class ExtendedCountSketch:
    def __init__(self, depth: int, width: int, h_coefficients=None, g_coefficients=None):
        self.mDepth = depth
        self.mWidth = width
        self.mRandomGenerator = random.SystemRandom()

        self.mCounters = [[0 for _ in range(width)] for _ in range(depth)]
        self.mSafeCounters = None
        self.mStates = [[0 for _ in range(width)] for _ in range(depth)]

        if h_coefficients and g_coefficients:
            self.mHCoefficients = h_coefficients
            self.mGCoefficients = g_coefficients
        else:
            self.mHCoefficients = [
                [self._random_large_prime() for _ in range(depth)],
                [self._relative_prime(self._random_large_prime()) for _ in range(depth)]
            ]
            self.mGCoefficients = [
                [self._random_large_prime() for _ in range(depth)],
                [self._relative_prime(self._random_large_prime()) for _ in range(depth)]
            ]

    def _gcd(self, a: int, b: int) -> int:
        while b != 0:
            tmp = a % b
            a = b
            b = tmp
        return a

    def _relative_prime(self, n: int) -> int:
        r = self._random_large_prime()
        t = self._gcd(r, n)
        while t > 1:
            r //= t
            t = self._gcd(r, n)
        return r

    def _random_large_prime(self) -> int:
        return self.mRandomGenerator.randint(1, LARGE_PRIME)

    def _hash(self, index: int, key: int) -> int:
        ip = int(ipaddress.IPv4Address(key))
        return ((self.mHCoefficients[0][index] * ip + self.mHCoefficients[1][index]) % LARGE_PRIME) % self.mWidth

    def _ghash(self, index: int, key: int) -> int:
        ip = int(ipaddress.IPv4Address(key))
        return 2 * (((self.mGCoefficients[0][index] * ip + self.mGCoefficients[1][index]) % LARGE_PRIME) % 2) - 1

    def update(self, key: int) -> int:
        counts = []
        for i in range(self.mDepth):
            h = self._hash(i, key)
            g = self._ghash(i, key)

            if self.mStates[i][h] != win_id:
                self.mCounters[i][h] = g
                self.mStates[i][h] = win_id
            else:
                self.mCounters[i][h] += g

            counts.append(g * self.mCounters[i][h])

        counts.sort()
        size = len(counts)
        if size % 2 == 0:
            return (counts[size // 2 - 1] + counts[size // 2]) // 2
        else:
            return counts[size // 2]

    def copy_sketch(self):
        self.mSafeCounters = [row[:] for row in self.mCounters]

    def estimate(self, key: int) -> int:
        counts = []
        for i in range(self.mDepth):
            h = self._hash(i, key)
            g = self._ghash(i, key)
            counts.append(g * self.mCounters[i][h])

        counts.sort()
        size = len(counts)
        if size % 2 == 0:
            return (counts[size // 2 - 1] + counts[size // 2]) // 2
        else:
            return counts[size // 2]

    def estimate_safe_sketch(self, key: int) -> int:
        if self.mSafeCounters is None:
            self.copy_sketch()

        counts = []
        for i in range(self.mDepth):
            h = self._hash(i, key)
            g = self._ghash(i, key)
            counts.append(g * self.mSafeCounters[i][h])

        counts.sort()
        size = len(counts)
        if size % 2 == 0:
            return (counts[size // 2 - 1] + counts[size // 2]) // 2
        else:
            return counts[size // 2]

class CountSketch:
    def __init__(self, width, depth):
        self.width = width
        self.depth = depth
        self.counters = np.zeros((depth, width), dtype=int)
        self.states = np.zeros((depth, width), dtype=int)
        self.safe_counters = None
        self.hash_funcs = [
            (lambda x, a=a, b=b: (a * hash(x) + b) % self.width)
            for a, b in zip(np.random.randint(1, 1000, depth), np.random.randint(1, 1000, depth))
        ]

    def update(self, key):
        for i, h in enumerate(self.hash_funcs):
            idx = h(key)

            if self.states[i, idx] != win_id:
                self.counters[i, idx] = 1
                self.states[i, idx] = win_id
            else:
                self.counters[i, idx] += 1

        est = self.estimate(key)
        return est

    def copy_sketch(self):
        self.safe_counters = np.copy(self.counters)

    def estimate(self, key):
        estimates = [self.counters[i, h(key)] for i, h in enumerate(self.hash_funcs)]
        return median(estimates)

    def estimate_safe_sketch(self, key):
        if self.safe_counters is None:
            self.copy_sketch()

        estimates = [self.safe_counters[i, h(key)] for i, h in enumerate(self.hash_funcs)]
        return median(estimates)

class Detector:
    def __init__(self):
        self.sketch_src = CountSketch(width, depth)
        self.sketch_dst = CountSketch(width, depth)

        self.src_ewma = None
        self.dst_ewma = None
        self.src_ewmmd = None
        self.dst_ewmmd = None

        # 0: SAFE; 1: DEFENSE ACTIVE; 2: DEFENSE COOLDOWN
        self.state = 0

    def process_window(self, packets):
        src_s = 0
        des_s = 0
        for src_ip, dst_ip in packets:
            src_f = self.sketch_src.update(src_ip)
            des_f = self.sketch_dst.update(dst_ip)

            if src_f == 1:
                src_s = src_s + src_f * math.log2(src_f)
            elif src_f > 1:
                src_s = src_s + src_f * math.log2(src_f) - (src_f - 1) * math.log2(src_f - 1)

            if des_f == 1:
                des_s = des_s + des_f * math.log2(des_f)
            elif des_f > 1:
                des_s = des_s + des_f * math.log2(des_f) - (des_f - 1) * math.log2(des_f - 1)

        src_entropy = math.log2(WIN_SIZE) - (1 / WIN_SIZE) * src_s
        dst_entropy = math.log2(WIN_SIZE) - (1 / WIN_SIZE) * des_s

        src_list.append(src_entropy)
        dst_list.append(dst_entropy)

        detected = False
        if self.src_ewma is None:
            self.src_ewma = src_entropy
            self.dst_ewma = dst_entropy
            self.src_ewmmd = 1
            self.dst_ewmmd = 1
        else:
            src_anomalous = (src_entropy > (self.src_ewma + sensitivity_coefficient * self.src_ewmmd))
            dst_anomalous = (dst_entropy < (self.dst_ewma - sensitivity_coefficient * self.dst_ewmmd))

            detected = (src_anomalous or dst_anomalous)
            if not detected:
                self.src_ewma = smoothing_coefficient * src_entropy + (1 - smoothing_coefficient) * self.src_ewma
                self.dst_ewma = smoothing_coefficient * dst_entropy + (1 - smoothing_coefficient) * self.dst_ewma

                self.src_ewmmd = smoothing_coefficient * abs(self.src_ewma - src_entropy) + (1 - smoothing_coefficient) * self.src_ewmmd
                self.dst_ewmmd = smoothing_coefficient * abs(self.dst_ewma - dst_entropy) + (1 - smoothing_coefficient) * self.dst_ewmmd

        return detected

    def classify(self, detected, packets):
        res = 0
        if self.state != 0:
            for src_ip, dst_ip in packets:
                src_last_f = self.sketch_src.estimate(src_ip)
                src_safe_f = self.sketch_src.estimate_safe_sketch(src_ip)
                dst_last_f = self.sketch_dst.estimate(dst_ip)
                dst_safe_f = self.sketch_src.estimate_safe_sketch(dst_ip)

                src_v = src_last_f - src_safe_f
                dst_v = dst_last_f - dst_safe_f

                v = dst_v - src_v

                if v > mitigation_threshold:
                    res = 1

        if detected:
            self.state = min(self.state + 1, 2)
        else:
            self.sketch_src.copy_sketch()
            self.sketch_dst.copy_sketch()
            self.state = max(self.state - 1, 0)

        return res

if __name__ == "__main__":
    detector = Detector()

    pcap_files = ["C:/Users/HYJun/Downloads/11/11.pcap", "C:/Users/HYJun/Downloads/11/22.pcap", "C:/Users/HYJun/Downloads/11/33.pcap", "C:/Users/HYJun/Downloads/11/44.pcap", "C:/Users/HYJun/Downloads/11/55.pcap", "C:/Users/HYJun/Downloads/11/66.pcap"]

    traffic = []
    for pcap_file in pcap_files:
        packets = rdpcap(pcap_file)
        
        for pkt in packets:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                traffic.append((src_ip, dst_ip))
    
    for i in range(0, len(traffic), WIN_SIZE):
        window = traffic[i:i + WIN_SIZE]
        detected = detector.process_window(window)
        res = detector.classify(detected, window)
        win_id += 1
        print(f"Window {i // WIN_SIZE}: Anomaly detected: {detected}")


    x = range(len(src_list))
    plt.plot(x, src_list, label="src_list", color='b', marker='o')
    plt.plot(x, dst_list, label="dst_list", color='r', marker='x')

    plt.title("")
    plt.xlabel("Index")
    plt.ylabel("Values")
    plt.legend()
    plt.show()
