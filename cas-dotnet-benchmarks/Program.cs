using BenchmarkDotNet.Running;
using cas_dotnet_benchmarks;

var summary = BenchmarkRunner.Run<PasswordHasherBenchmarks>();