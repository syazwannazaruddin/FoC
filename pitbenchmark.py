import csv
import matplotlib.pyplot as plt

FILE_SIZES = ["1 KB", "100 KB", "1 MB"]
ALGORITHMS = ["LFSR", "AES-256-GCM"]


def read_results():
    results = {}

    with open("benchmark_results.csv", "r", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            algorithm = row["Algorithm"]
            file_size = row["File size"]

            if algorithm not in results:
                results[algorithm] = {}

            results[algorithm][file_size] = row

    return results


def create_bar_chart(results, column_name, title, y_label, output_file):
    x_positions = list(range(len(FILE_SIZES)))
    bar_width = 0.35

    plt.figure(figsize=(9, 5))

    for index, algorithm in enumerate(ALGORITHMS):
        values = [
            float(results[algorithm][file_size][column_name])
            for file_size in FILE_SIZES
        ]

        positions = [
            position + (index - 0.5) * bar_width
            for position in x_positions
        ]

        plt.bar(positions, values, width=bar_width, label=algorithm)

    plt.xticks(x_positions, FILE_SIZES)
    plt.xlabel("File Size")
    plt.ylabel(y_label)
    plt.title(title)
    plt.legend()
    plt.grid(axis="y", linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(output_file, dpi=300)
    plt.close()

    print(f"Created {output_file}")


def main():
    results = read_results()

    create_bar_chart(
        results,
        "Encryption average ms",
        "Encryption Time Comparison",
        "Average Encryption Time (ms)",
        "encryption_time.png",
    )

    create_bar_chart(
        results,
        "Decryption average ms",
        "Decryption Time Comparison",
        "Average Decryption Time (ms)",
        "decryption_time.png",
    )

    create_bar_chart(
        results,
        "Encryption throughput MB/s",
        "Encryption Throughput Comparison",
        "Throughput (MB/s)",
        "throughput.png",
    )


if __name__ == "__main__":
    main()