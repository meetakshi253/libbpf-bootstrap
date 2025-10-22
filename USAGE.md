# NFSVFSSlower

NFSVFSSlower is an eBPF program that traces and measures the latency of various NFSv4 file and inode operations as they are called by the VFS layer. It starts capturing diagnostic logs automatically and stops when any traced operation exceeds a user-defined latency threshold.

For detailed usage information, run: `nfsvfsslower -h`

## Running NFSVFSSlower (Prebuilt Binary)

### Prerequisites

Ensure your target VM/computer/Kubernetes node has:

- **Kernel version**: 5.15
- **BTF information exposed**: Verify `/sys/kernel/btf/vmlinux` exists:
  ```bash
  ls /sys/kernel/btf/vmlinux
  ```
- For building from source, see the [Building from Source](#building-and-running-nfsvfsslower-from-source) section

### Installation

1. **Clone the repository and checkout the correct branch:**
   ```bash
   git clone --recurse-submodules https://github.com/meetakshi253/libbpf-bootstrap.git
   cd libbpf-bootstrap
   git checkout nfsdiagnostics
   ```

2. **Run the prebuilt binary:**
   ```bash
   cd examples/c
   sudo ./nfsvfsslower --file --inode -l <cooldown> -m <latency_threshold_ms> --capturenetwork
   ```

- **`--inode`** and **`--file`**: Trace inode and file operations (can use individually or together)
- **`-m <threshold>`**: Set latency threshold in milliseconds (default: 10ms). When operations exceed this threshold, diagnostics capture stops and anomaly is logged to syslog
- **`-l <cooldown>`**: Enable NFSdiagnostics capture with automatic restart capability. The cooldown period (in seconds) specifies the wait time between subsequent captures, after the previous capture ends when a latency threshold breach occurs.
- **`--capturenetwork`**: Instruct `nfsdiagnostics.sh` script to collect network traffic via tcpdump

## Building and Running NFSVFSSlower from Source

### Build Requirements

- GCC or Clang compiler
- libbpf development headers
- BPF Compile Once-Run Everywhere (CO-RE) support

### Build Instructions

1. **Install dependencies** (Ubuntu/Debian):
   ```bash
   sudo apt update
   sudo apt install clang libelf1 libelf-dev zlib1g-dev gcc make pkg-config
   ```

2. **Build the tool:**
   ```bash
   cd libbpf-bootstrap/examples/c
   make nfsvfsslower
   ```

3. **Run the compiled binary:**
   ```bash
   sudo ./nfsvfsslower --file --inode -l <cooldown> -m <latency_threshold_ms> --capturenetwork
   ```

### Troubleshooting

- **Permission denied**: Ensure you run with `sudo` privileges
- **BTF not found**: Verify kernel BTF support is enabled
- **Build errors**: Check that all dependencies are properly installed

---

For additional support or to report issues, visit the [GitHub repository](https://github.com/meetakshi253/libbpf-bootstrap).