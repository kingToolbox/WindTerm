# Generate 100MB data.
if [ ! -f "./benchmark_randomdata" ];then
cat /dev/urandom | base64 | dd of=./benchmark_randomdata bs=1024 count=100KB
fi
echo "Benchmark Result:"
{ time dd if=./benchmark_randomdata bs=10240; }
