# Stage 10 qualification hosts

This record answers REL-01 (issue #43): the reproducible execution
environments for the two native release targets, the immutable tool images
built from the repository scripts, the storage tuple the qualification jobs
must run on, and the runbook that keeps campaigns from distorting one
another. Qualification output stays outside the candidate source; every
record named here lives under the qualification directory of its host and
is bound by digest.

## x86_64-unknown-linux-gnu: prepared

Host identity, recorded on 2026-09-15 in `host.json` (SHA-256
`5babfc287d0ab527b0892092ac3e1a9457833a5a766d690f0dc2fb642405cabc`) under
`/mnt/data/agenc-dev/qualification/x86_64/`:

| Item | Value |
| --- | --- |
| Kernel | Linux 7.0.0-31-generic (#31~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC), Ubuntu 24.04.5 LTS |
| CPU / RAM | AMD Ryzen Threadripper PRO 9975WX, 64 logical CPUs; 1,055,751,292 KiB (1,006 GiB) |
| Qualification filesystem | ext4 on `/dev/nvme0n1p2` (WD_BLACK SN850X 8000GB, NVMe, non-rotational), block size 4,096, mount options `rw,relatime,stripe=64`; the root and `/home` filesystem |
| Development filesystem | xfs on `/dev/mapper/datavg-datalv` (`/mnt/data`); used only for development build targets, never for a storage measurement |
| Rust | rustc 1.98.0 (88d9e12ae 2026-08-18), host `x86_64-unknown-linux-gnu`, with clippy, rustfmt and llvm-tools; fuzz toolchain nightly-2026-08-24 (rustc 1.100.0-nightly fb6531d55), cargo-fuzz 0.13.2 |
| Container runtime | Docker 29.1.3 (BuildKit); the invoking user is in the `docker` group |
| Policy and drill tools | Python 3.13.13, tor, `setfacl`/`getfacl`, systemd user manager with delegated scopes (`systemd-run --user --scope -p Delegate=yes`), cgroup v2 controllers `cpuset cpu io memory hugetlb pids rdma misc dmem` |

Images built with the repository scripts on this host, recorded beside their
build logs (the records carry the Dockerfile digest, the base image digest,
the compiler, and the package list or client pins they contain):

| Image | Script | Image ID | Record |
| --- | --- | --- | --- |
| Release build image (`conformance/release/Dockerfile`, Ubuntu 24.04 by digest with the host's pinned Rust 1.98.0 sysroot) | `python3 scripts/build-release-image.py --output /mnt/data/agenc-dev/qualification/x86_64/release-image` | `sha256:eec65ff78d5798c0af941a4486474e1c52349060227f8c808d07fc3da572c462` | `release-image/image.json`, SHA-256 `b73badf7d5e564503df65c9bd43b0d04d2a86bfe38e173f44965c50ad6098b1f` |
| Client tools image (`conformance/clients/Dockerfile`: patched WeeChat 4.10.1 `f5601e9`, patched irssi 1.4.5 `bcf07a2`, chutney `6cc1588`, tor, tcpdump) | `python3 scripts/build-qualification-tools.py --output /mnt/data/agenc-dev/qualification/x86_64/tools-image` | `sha256:230f304ff28a4cac3711d578c4a2cfb4f691b4a2f9345a1b04832f5f44eea710` | `tools-image/tools.json`, SHA-256 `6d658a9b819f2f3e8867e4f29c194fc6a8fab0efcbcb412d4eebe1043db2833a` |

`python3 scripts/qualify-release.py check` lists the thirty-one campaign
jobs, both native targets and the 90 percent release branch floor on this
host. `rustc -vV` reports the native target above. The frozen candidate
build (`scripts/build-release.py build --image <release image>`) and the
candidate preparation (`qualify-release.py prepare`, one build record and
one client tools record per target) belong to REL-04; both records this
host needs for them exist.

## aarch64-unknown-linux-gnu: external blocker

No native AArch64 host is available to the qualification agent, and
compiling for AArch64 on this x86_64 host proves nothing about native
qualification. The repository's hosted path,
`.github/workflows/stage-10-aarch64.yml` on an `ubuntu-24.04-arm` runner,
builds the release image and the reproduced artifacts but cannot start
while the organization-level GitHub Actions block recorded in issue #41
persists, and it only yields the build record: the AArch64 qualification
jobs themselves need a native AArch64 host with the same ext4 tuple class,
delegated cgroups, Docker, Tor and the pinned toolchains. Provisioning one
(or an ARM cloud instance with a dedicated NVMe ext4 volume) needs an
infrastructure owner. Until then the AArch64 half of REL-01 is blocked
externally, not substituted; no memory-backed or emulated environment is
recorded in its place.

## Runbook: isolation, reservation, retention and resumption

The rules below came from measurement, not policy: on 2026-09-15 a
serialized gate lost the storage qualification's free-space boundary
(`QualificationFailure { error: StaleState }`) to a client-tools image
build that was writing to the same ext4 device at the same time, and gates
sharing one target directory reused stale artifacts across worktrees until
each gate started from a clean target.

1. **One filesystem, one campaign.** The storage job
   (`qualify-stage-ten-storage.py`, S10-006) and the capacity and soak jobs
   run with nothing else writing to `/dev/nvme0n1p2`: no image builds, no
   parallel gates, no development builds on the root filesystem
   (development targets live on `/mnt/data`). Free-space samples are taken
   as the scripts take them; bounds and retry policy are not adjusted to
   absorb interference.
2. **Bounded fuzz workers.** Each of the 21 fuzz targets needs 24 CPU-hours
   on its own; run them under `systemd-run --user --scope -p Delegate=yes
   -p AllowedCPUs=<set>` with at most 16 workers (`maximum_workers` in
   `conformance/stage-ten-qualification.toml`) pinned away from the CPUs
   reserved for a concurrently running capacity or soak job, and never on
   the same host during a storage measurement.
3. **Reservation.** Before a campaign, reserve the host: stop the
   serialized gate queue, confirm `docker ps` shows no build, and record
   the free space of the qualification filesystem. The seven-day soak needs
   the host for seven elapsed days; schedule fuzz campaigns before or after
   it, not during.
4. **Where output goes.** Candidates, job attempts, logs and samples live
   under `/mnt/data/agenc-dev/qualification/<target>/`, never inside a
   worktree. `qualify-release.py` bounds every log to `maximum_log_bytes`
   and every record to `maximum_record_bytes`; failure logs are kept in
   place under the candidate's job directory and are never truncated by a
   retry.
5. **Resumption.** A job interrupted by a host restart resumes with
   `python3 scripts/qualify-release.py resume --candidate <dir> --job <id>`;
   `status --candidate <dir>` shows every attempt per target. A job that
   failed on a measurement rule reruns from the start with
   `run`; its earlier attempt stays recorded.
6. **Access for another agent.** The host is reachable only through the
   repository owner's account; no credentials are recorded here. The
   qualification directory, the records named above and the tools in the
   table are everything a second authorized agent needs to reproduce the
   x86_64 preparation: check out the exact revision, run the two image
   scripts, compare the image records' Dockerfile digests and client pins
   with the committed files, and run `qualify-release.py check`.
