import PyPDF2
import itertools
import multiprocessing
import argparse
import time
from multiprocessing import Value, Lock
from datetime import datetime


def validate_date_suffix(suffix):
    """
    Validate if the provided suffix is a valid date in the format DDMMYY.
    :param suffix: 6-digit suffix to validate.
    :return: True if valid, False otherwise.
    """
    if len(suffix) != 6:
        return False
    try:
        datetime.strptime(suffix, "%d%m%y")
        return True
    except ValueError:
        return False


def test_password_range(pdf_path, fixed_part, is_prefix, start, end, total_attempts, lock, queue):
    """
    Test a range of passwords with a fixed prefix or suffix.
    :param pdf_path: Path to the PDF file.
    :param fixed_part: Fixed prefix (5 digits) or suffix (6 digits).
    :param is_prefix: True if fixed part is prefix, False if suffix.
    :param start: Start index for permutations.
    :param end: End index for permutations.
    :param total_attempts: Shared value to count total attempts.
    :param lock: Lock to synchronize updates to shared values.
    :param queue: Queue to report success.
    """
    digits = "0123456789"
    with open(pdf_path, "rb") as pdf_file:
        pdf_reader = PyPDF2.PdfReader(pdf_file)

        for combination in itertools.islice(itertools.product(digits, repeat=11 - len(fixed_part)), start, end):
            remaining_part = "".join(combination)
            password = fixed_part + remaining_part if is_prefix else remaining_part + fixed_part

            with lock:
                # print(f"Testing password: {password}")
                total_attempts.value += 1

            try:
                if pdf_reader.decrypt(password) == 1:
                    print(f"Password found: {password}")
                    queue.put(password)  # Send password to the queue
                    return
            except Exception:
                continue

    queue.put(None)  # Signal that this process did not find the password


def monitor_progress(total_attempts, stop_flag, lock):
    """
    Monitor progress and print the total attempts every 20 seconds.
    :param total_attempts: Shared value to track total password attempts.
    :param stop_flag: Flag to stop the monitoring when processes finish.
    :param lock: Lock to safely read shared values.
    """
    while not stop_flag.value:
        time.sleep(20)  # Wait for 20 seconds
        with lock:
            print(f"Total iterations so far: {total_attempts.value}")


def parallel_brute_force(pdf_path, fixed_part, is_prefix, num_processes):
    """
    Parallel brute-force password cracking for a PDF file with fixed digits.
    :param pdf_path: Path to the PDF file.
    :param fixed_part: Fixed prefix or suffix.
    :param is_prefix: True if fixed part is prefix, False if suffix.
    :param num_processes: Number of processes to use.
    """
    digits = "0123456789"
    total_combinations = 10 ** (11 - len(fixed_part))  # Total permutations of the remaining digits
    chunk_size = total_combinations // num_processes  # Split work across processes

    # Shared variables for tracking progress and signaling
    total_attempts = Value('i', 0)
    stop_flag = Value('b', False)
    lock = Lock()
    queue = multiprocessing.Queue()

    # Start a monitoring process for tracking progress
    monitor_process = multiprocessing.Process(target=monitor_progress, args=(total_attempts, stop_flag, lock))
    monitor_process.start()

    # Start parallel brute-forcing processes
    processes = []
    for i in range(num_processes):
        start = i * chunk_size
        end = (i + 1) * chunk_size if i < num_processes - 1 else total_combinations
        process = multiprocessing.Process(target=test_password_range, args=(pdf_path, fixed_part, is_prefix, start, end, total_attempts, lock, queue))
        processes.append(process)
        process.start()

    # Wait for processes to finish
    found_password = None
    for process in processes:
        process.join()
        # Check if any process found the password
        while not queue.empty():
            result = queue.get()
            if result:
                found_password = result
                break

    # Signal monitoring process to stop
    with stop_flag.get_lock():
        stop_flag.value = True
    monitor_process.join()

    if found_password:
        print(f"Password successfully found: {found_password}")
    else:
        print("Password not found. Exhausted all combinations.")


if __name__ == "__main__":
    # Command-line arguments
    parser = argparse.ArgumentParser(description="Brute-force an 11-digit PDF password with a fixed prefix or suffix.")
    parser.add_argument("file", help="Path to the PDF file")
    parser.add_argument("--prefix", help="Fixed first 5 digits of the password (optional)")
    parser.add_argument("--suffix", help="Fixed last 6 digits of the password (optional, must represent a valid date)")
    parser.add_argument("--processes", type=int, default=multiprocessing.cpu_count(),
                        help="Number of processes to use (default: CPU count)")
    args = parser.parse_args()

    # Validate input
    if args.prefix and args.suffix:
        print("Specify either --prefix or --suffix, not both.")
        exit(1)
    if args.prefix and len(args.prefix) != 5:
        print("Prefix must be exactly 5 digits.")
        exit(1)
    if args.suffix:
        if len(args.suffix) != 6 or not validate_date_suffix(args.suffix):
            print("Suffix must be a valid 6-digit date in the format DDMMYY.")
            exit(1)
    if not args.prefix and not args.suffix:
        print("You must specify either --prefix or --suffix.")
        exit(1)

    # Determine if the fixed part is a prefix or suffix
    fixed_part = args.prefix if args.prefix else args.suffix
    is_prefix = bool(args.prefix)

    # Start brute-forcing
    parallel_brute_force(args.file, fixed_part, is_prefix, args.processes)
