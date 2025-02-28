import re
import sys
import matplotlib.pyplot as plt

def parse_benchmark_results(filename):
    """
    Parses a Criterion benchmark output file and extracts proof generation and verification times.

    Args:
        filename (str): The file containing Criterion benchmark output.

    Returns:
        ballot_sizes (list): List of ballot sizes.
        proof_times (list): List of proof generation times (ms).
        verification_times (list): List of proof verification times (ms).
    """
    ballot_sizes = []
    proof_times = {}
    verification_times = {}

    benchmark_regex = re.compile(r"(Generate|Verify) Shuffle Proof/(\d+)")
    time_regex = re.compile(r"time:\s+\[\s*([\d\.]+) ms\s+([\d\.]+) ms\s+([\d\.]+) ms\s*\]")

    with open(filename, "r") as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        benchmark_match = benchmark_regex.search(lines[i])

        if benchmark_match and i + 1 < len(lines):  # Ensure the next line contains time
            benchmark_type = benchmark_match.group(1)  # "Generate" or "Verify"
            ballot_size = int(benchmark_match.group(2))  # Extract ballot size

            time_match = time_regex.search(lines[i + 1])  # Look at the next line for time
            if time_match:
                median_time = float(time_match.group(2))  # Extract middle time value

                if benchmark_type == "Generate":
                    proof_times[ballot_size] = median_time
                else:
                    verification_times[ballot_size] = median_time

                if ballot_size not in ballot_sizes:
                    ballot_sizes.append(ballot_size)

        i += 1

    # Ensure sorted ballot sizes
    ballot_sizes = sorted(ballot_sizes)
    proof_list = [proof_times.get(size, None) for size in ballot_sizes]
    verification_list = [verification_times.get(size, None) for size in ballot_sizes]

    # Filter out missing data
    valid_indices = [i for i in range(len(ballot_sizes)) if proof_list[i] is not None and verification_list[i] is not None]
    ballot_sizes = [ballot_sizes[i] for i in valid_indices]
    proof_list = [proof_list[i] for i in valid_indices]
    verification_list = [verification_list[i] for i in valid_indices]

    print(f"✅ Extracted {len(ballot_sizes)} ballot sizes: {ballot_sizes}")
    print(f"✅ Extracted {len(proof_list)} proof times: {proof_list}")
    print(f"✅ Extracted {len(verification_list)} verification times: {verification_list}")

    return ballot_sizes, proof_list, verification_list

def plot_benchmark_results(ballot_sizes, proof_times, verification_times):
    """
    Plots the benchmark results: Ballot Size vs. Proof & Verification Time.

    Args:
        ballot_sizes (list): List of ballot sizes.
        proof_times (list): List of proof generation times (ms).
        verification_times (list): List of proof verification times (ms).
    """
    plt.figure(figsize=(10, 6))
    plt.plot(ballot_sizes, proof_times, marker='o', linestyle='-', label='Proof Generation Time (ms)')
    plt.plot(ballot_sizes, verification_times, marker='s', linestyle='--', label='Verification Time (ms)')

    plt.xlabel("Ballot Size")
    plt.ylabel("Time (ms)")
    plt.title("Ballot Size vs. Proof & Verification Time")
    plt.legend()
    plt.grid(True)

    # Fix non-interactive error by saving instead of showing
    plt.savefig("benchmark_plot.png")
    print("📊 Graph saved as benchmark_plot.png")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python benchmark_plot.py <benchmark_output.txt>")
        sys.exit(1)

    filename = sys.argv[1]
    ballot_sizes, proof_times, verification_times = parse_benchmark_results(filename)

    if not ballot_sizes or not proof_times or not verification_times:
        print("❌ Error: Missing data. Ensure the input file contains valid Criterion benchmark output.")
        sys.exit(1)

    plot_benchmark_results(ballot_sizes, proof_times, verification_times)
