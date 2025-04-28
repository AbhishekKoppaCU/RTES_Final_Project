import matplotlib.pyplot as plt
import pandas as pd
import glob

def plot_histogram(file_path, service_name):
    data = pd.read_csv(file_path)
    times = data.values.flatten()

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

    # Set X-axis limit
    plt.xlim(0, max_val * 1.2)

    plt.show()

def main():
    files = glob.glob("*_exec_times.csv")
    for file in files:
        service_name = file.replace("_exec_times.csv", "")
        plot_histogram(file, service_name)

if __name__ == "__main__":
    main()
