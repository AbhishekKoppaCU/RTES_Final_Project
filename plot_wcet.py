import matplotlib.pyplot as plt
import pandas as pd
import glob
import os

def plot_histogram(file_path, service_name):
    if os.stat(file_path).st_size == 0:
        print(f"Skipping empty file: {file_path}")
        return  # File is empty, skip

    data = pd.read_csv(file_path)

    # Sometimes even a non-empty file can have no rows after header
    if data.empty:
        print(f"Skipping file with no data rows: {file_path}")
        return

    times = data.values.flatten()

    # Additional safeguard if times is somehow empty
    if times.size == 0:
        print(f"No timing data to plot for {service_name}. Skipping.")
        return

    max_val = times.max()

    # Decide bin size
    if max_val > 10000:
        bins = 100
    elif max_val > 1000:
        bins = 50
    else:
        bins = 30

    plt.hist(times, bins=bins, edgecolor='black')
    plt.title(f"{service_name} Execution Time Histogram\n(WCET = {max_val:.2f} us)")
    plt.xlabel("Execution Time (us)")
    plt.ylabel("Frequency")
    plt.grid(True)

    # Mark WCET line
    plt.axvline(max_val, color='red', linestyle='dashed', linewidth=2, label=f"WCET = {max_val:.2f} us")
    plt.legend()

    plt.xlim(0, max_val * 1.2)

    plt.show()

def main():
    files = glob.glob("*_exec_times.csv")
    if not files:
        print("No CSV files found to plot.")
        return

    for file in files:
        service_name = file.replace("_exec_times.csv", "")
        plot_histogram(file, service_name)

if __name__ == "__main__":
    main()
