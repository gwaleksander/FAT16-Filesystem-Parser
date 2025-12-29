# FAT16 File System Reader

A low-level system utility designed to parse FAT16 file system images by directly interacting with block devices (simulated as files). This project implements the core logic of an operating system's file system driver.

## 🛠 Project Architecture & Features
- **Abstraction Layer:** Implements a `disk_t` block device API, ensuring that the parser works with 512-byte sectors rather than standard file streams, mimicking real hardware interaction.
- **POSIX-Compliant Error Handling:** Fully integrated with `errno.h`, providing standardized error codes (`ENOENT`, `ENXIO`, `EISDIR`) for robust system integration.
- **Boot Sector Parsing:** Decodes the BIOS Parameter Block (BPB) to determine volume geometry, cluster size, and FAT locations.
- **Directory Traversal:** Supports opening, reading, and closing directories, specifically optimized for the Root Directory.
- **File Operations:**
    - `file_open`: Locates files by name and validates attributes.
    - `file_read`: Reconstructs file data by traversing the Cluster Chain in the FAT table.
    - `file_seek`: Implements byte-level positioning within the cluster-chained data stream.

## 🧩 Technical Specifications
- **Cluster Chaining:** Dynamic navigation through the File Allocation Table to handle non-contiguous file storage.
- **Memory Efficiency:** Designed to work with limited memory buffers; does not load the entire disk image into RAM.
- **Data Integrity:** Validates volume signatures (`0x55AA`) and ensures consistency between redundant FAT tables.

## 📊 Demonstrated Skills
- **Binary Forensics:** Deep understanding of the physical layout of FAT file systems.
- **System API Design:** Building a hierarchical handle system: `disk_t` -> `volume_t` -> `file_t`/`dir_t`.
- **Low-level I/O:** Manual byte-offset calculation and binary stream management.
