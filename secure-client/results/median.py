import statistics
import sys

values = []
for line in sys.stdin:
  line = line.strip()
  line = line.split()
  values.append(float(line[0]))

print (str(statistics.median(values)) + "s")
