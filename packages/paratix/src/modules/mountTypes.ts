/**
 * The top-most live mount at a mountpoint, as reported by
 * `findmnt --pairs --nofsroot --mountpoint <path>` with every `\xNN` escape
 * already decoded.
 */
export type LiveMount = {
  /** Filesystem root of the mount inside its superblock (`/` for a plain mount, e.g. `/docker` for a bind of a subdirectory). */
  fsroot: string
  fstype: string
  /** Mount ID (`ID` column). */
  id: string
  /** Device number of the backing superblock (`MAJ:MIN` column). */
  majMin: string
  /** All mount options (VFS flags plus superblock options, `OPTIONS` column). */
  options: string
  /**
   * Mount ID of the parent mount, read from `/proc/self/mountinfo` (findmnt's
   * `PARENT` column needs util-linux 2.37); `""` when it could not be read.
   */
  parent: string
  /** Mount source without the `[fsroot]` suffix (`SOURCE` column, `--nofsroot`). */
  source: string
  /** Per-mount VFS flags only (`VFS-OPTIONS` column). */
  vfsOptions: string
}

/**
 * The resolved identity of a desired bind-mount source: the canonical path
 * plus the `MAJ:MIN` and FSROOT a bind of that path would show at the target.
 */
export type BindSource = {
  /** Desired FSROOT: containing mount FSROOT joined with the path below its TARGET. */
  fsroot: string
  /** Device number of the mount that contains the resolved source. */
  majMin: string
  /** The source path as resolved by `readlink -f`. */
  resolved: string
  /** SOURCE of the containing mount; used only in messages. */
  source: string
}

/**
 * The kind of live change `mount.present` applied before persisting fstab:
 * - `unchanged`: the live mount already matched;
 * - `fresh`: nothing was mounted, a new mount was created;
 * - `remount`: identity matched, only flags/options were remounted;
 * - `replace`: identity drifted, the old mount was unmounted and replaced.
 */
export type LiveMountChange = "fresh" | "remount" | "replace" | "unchanged"
