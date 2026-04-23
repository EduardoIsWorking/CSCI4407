# task6_statistical_analysis.py
# CSCI 4407 - Assignment 3
# Task 6: Statistical Evaluation of Results
#
# This script:
# 1. stores the observed pattern counts from Task 5
# 2. computes the expected frequency using E(P) = N / 2^|P|
# 3. prints a comparison table
# 4. computes the deviation between observed and expected values
# 5. generates one graph showing Expected, Case A, Case B, and Case C
#
# Note:
# If you are using Jupyter and matplotlib still fails, run this file directly
# from the terminal while your virtual environment is activated:
#     python3 task6_statistical_analysis.py

import math
import matplotlib.pyplot as plt

# Total sequence length
N = 1_000_000

# Observed counts from your Task 5 output
observed = {
    "8 bits": {
        "length": 8,
        "A": 3996,
        "B": 125000,
        "C": 3961
    },
    "16 bits": {
        "length": 16,
        "A": 31,
        "B": 124999,
        "C": 26
    },
    "32 bits": {
        "length": 32,
        "A": 0,
        "B": 124997,
        "C": 0
    }
}


def expected_frequency(n, pattern_length):
    """
    Compute expected frequency using:
    E(P) = N / 2^|P|
    """
    return n / (2 ** pattern_length)


def absolute_deviation(observed_value, expected_value):
    """
    Return the absolute difference between observed and expected.
    """
    return abs(observed_value - expected_value)


def print_results_table():
    """
    Print a formatted table showing expected values, observed values,
    and deviations for each pattern length.
    """
    print("=" * 110)
    print("TASK 6: OBSERVED VS EXPECTED FREQUENCY ANALYSIS")
    print("=" * 110)
    print(
        f"{'Pattern':<10}"
        f"{'Expected':<15}"
        f"{'Case A':<12}"
        f"{'Dev A':<15}"
        f"{'Case B':<12}"
        f"{'Dev B':<15}"
        f"{'Case C':<12}"
        f"{'Dev C':<15}"
    )

    for label, data in observed.items():
        exp = expected_frequency(N, data["length"])

        a = data["A"]
        b = data["B"]
        c = data["C"]

        dev_a = absolute_deviation(a, exp)
        dev_b = absolute_deviation(b, exp)
        dev_c = absolute_deviation(c, exp)

        print(
            f"{label:<10}"
            f"{exp:<15.6f}"
            f"{a:<12}"
            f"{dev_a:<15.6f}"
            f"{b:<12}"
            f"{dev_b:<15.6f}"
            f"{c:<12}"
            f"{dev_c:<15.6f}"
        )


def create_graph():
    """
    Create one graph showing Expected, Case A, Case B, and Case C.
    A logarithmic y-scale is used because Case B is much larger than the others.
    """
    labels = []
    expected_vals = []
    case_a_vals = []
    case_b_vals = []
    case_c_vals = []

    for label, data in observed.items():
        labels.append(label)
        expected_vals.append(expected_frequency(N, data["length"]))
        case_a_vals.append(data["A"])
        case_b_vals.append(data["B"])
        case_c_vals.append(data["C"])

    x = range(len(labels))
    width = 0.2

    plt.figure(figsize=(11, 6))

    plt.bar([i - 1.5 * width for i in x], expected_vals, width=width, label="Expected")
    plt.bar([i - 0.5 * width for i in x], case_a_vals, width=width, label="Case A")
    plt.bar([i + 0.5 * width for i in x], case_b_vals, width=width, label="Case B")
    plt.bar([i + 1.5 * width for i in x], case_c_vals, width=width, label="Case C")

    plt.xticks(list(x), labels)
    plt.xlabel("Pattern Length")
    plt.ylabel("Frequency")
    plt.title("Observed vs Expected Pattern Frequencies")
    plt.yscale("log")  # helps make all bars visible due to very large Case B values
    plt.legend()
    plt.tight_layout()

    # Save graph to file
    plt.savefig("task6_observed_vs_expected.png", dpi=300)
    print("\nGraph saved as: task6_observed_vs_expected.png")

    # Show graph
    plt.show()


def main():
    print_results_table()
    create_graph()


if __name__ == "__main__":
    main()