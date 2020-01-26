from __future__ import print_function
import sys
import getopt

fail_under = None
max_difference = 0
read_location = None
save_location = None

argv = sys.argv[1:]

opts, args = getopt.getopt(
    argv, "s:r:", ["fail-under=", "max-difference=", "save=", "read="]
)
if args:
    raise ValueError("Unexpected parameters: {0}".format(args))
for opt, arg in opts:
    if opt == "-s" or opt == "--save":
        save_location = arg
    elif opt == "-r" or opt == "--read":
        read_location = arg
    elif opt == "--fail-under":
        fail_under = float(arg) / 100.0
    elif opt == "--max-difference":
        max_difference = float(arg) / 100.0
    else:
        raise ValueError("Unknown option: {0}".format(opt))

total_hits = 0
total_count = 0

for line in sys.stdin.readlines():
    if not line.startswith("ecdsa"):
        continue

    fields = line.split()
    hit, count = fields[1].split("/")
    total_hits += int(hit)
    total_count += int(count)

coverage = total_hits * 1.0 / total_count

if read_location:
    with open(read_location, "r") as f:
        old_coverage = float(f.read())
    print("Old coverage: {0:6.2f}%".format(old_coverage * 100))

if save_location:
    with open(save_location, "w") as f:
        f.write("{0:1.40f}".format(coverage))

print("Coverage: {0:6.2f}%".format(coverage * 100))

if read_location:
    print("Difference: {0:6.2f}%".format((old_coverage - coverage) * 100))

if fail_under and coverage < fail_under:
    print("ERROR: Insufficient coverage.", file=sys.stderr)
    sys.exit(1)

if read_location and coverage - old_coverage < max_difference:
    print("ERROR: Too big decrease in coverage", file=sys.stderr)
    sys.exit(1)
