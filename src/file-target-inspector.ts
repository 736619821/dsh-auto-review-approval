/** Read-only filesystem evidence for one normalized file mutation. */

import type { ApprovalRequest } from '@deepseek-ai/dsh-user-approval'
import type {
  FileReviewAction,
  FileTargetInspectionResult,
} from './review-context.ts'

/**
 * Whether a path is absolute on POSIX *or* Windows, independent of the host.
 *
 * `node:path`'s `isAbsolute` answers for the host platform only, so a POSIX
 * workspace path (`/work/main`) reads as relative on a Windows host and this
 * inspector would fail closed before looking at the target at all. Execution
 * paths come from the DSH filesystem service, which may hand over either
 * convention; the guard has to accept both.
 */
function isAbsolutePath(path: string): boolean {
  return path.startsWith('/') || /^[A-Za-z]:[\\/]/.test(path) || path.startsWith('\\\\')
}

/** Minimal target identity used by a DSH filesystem implementation. */
export interface FileProbeTarget {
  readonly displayPath: string
}

/** Minimal metadata surface required for approval target inspection. */
export interface FileProbeInfo {
  readonly type: 'file' | 'directory' | 'other'
  readonly size?: number
}

/** Minimal path metadata surface required to detect a final symlink. */
export interface FileProbePathInfo {
  readonly type: 'file' | 'directory' | 'symlink' | 'other'
  readonly size?: number
}

/** Structural subset of the DSH filesystem service used by this plugin. */
export interface FileTargetFileSystem<TTarget extends FileProbeTarget> {
  resolve(path: string, options?: { cwd?: string; signal?: AbortSignal }): Promise<TTarget>
  processPath(target: TTarget): string
  contains(parent: TTarget, child: TTarget): boolean
  stat(target: TTarget, signal?: AbortSignal): Promise<FileProbeInfo | undefined>
  lstat(
    path: string,
    options?: { cwd?: string },
    signal?: AbortSignal,
  ): Promise<FileProbePathInfo | undefined>
}

/**
 * Resolve an action path the way the filesystem service would, without
 * `node:path` (which mishandles Unix paths on a Windows host).
 *
 * An ABSOLUTE path already names its own root: the workspace anchors a relative
 * one and nothing else. Appending it to the root instead turns `/etc/hosts`
 * into `/work/main/etc/hosts`, which then disagrees with the process path and
 * makes every absolute target look aliased — deferring each of those writes to
 * the human answerer.
 */
function lexicalResolve(root: string, filePath: string): string {
  const parts: string[] = filePath.startsWith('/')
    ? []
    : root.replace(/\/+$/, '').split('/').filter(part => part !== '')
  for (const part of filePath.split('/')) {
    if (part === '' || part === '.') continue
    if (part === '..') { parts.pop(); continue }
    parts.push(part)
  }
  return '/' + parts.join('/')
}

/** Inspect one exact normalized file action without reading file content. */
export type FileTargetInspector = (
  action: FileReviewAction,
  workspaceRoot: string | undefined,
  request: ApprovalRequest,
) => Promise<FileTargetInspectionResult>

/**
 * Create a target inspector over the mounted DSH filesystem service.
 * @param fs - mounted filesystem capability.
 * @returns a fail-closed read-only target inspector.
 */
export function createFileTargetInspector<TTarget extends FileProbeTarget>(
  fs: FileTargetFileSystem<TTarget>,
): FileTargetInspector {
  return async (action, workspaceRoot, request) => {
    if (workspaceRoot === undefined || workspaceRoot.trim() === '' || !isAbsolutePath(workspaceRoot)) {
      return { kind: 'human', reasonCode: 'file-target-unavailable' }
    }
    const filePath = action.arguments.file_path
    const signal = request.signal
    const pathInfo = await fs.lstat(filePath, { cwd: workspaceRoot }, signal)
    if (pathInfo?.type === 'symlink') {
      return { kind: 'human', reasonCode: 'file-target-symlink' }
    }

    const resolveOptions = { cwd: workspaceRoot, ...signal === undefined ? {} : { signal } }
    const workspaceTarget = await fs.resolve(workspaceRoot, resolveOptions)
    const target = await fs.resolve(filePath, resolveOptions)
    const processPath = fs.processPath(target)
    if (processPath.trim() === '' || !isAbsolutePath(processPath)) {
      return { kind: 'human', reasonCode: 'file-target-invalid' }
    }
    const lexicalPath = lexicalResolve(workspaceRoot, filePath)
    if (comparablePath(lexicalPath) !== comparablePath(processPath)) {
      return { kind: 'human', reasonCode: 'file-target-aliased' }
    }
    const targetInfo = await fs.stat(target, signal)
    if (!validPathInfo(pathInfo) || !validTargetInfo(targetInfo) || target.displayPath.trim() === '') {
      return { kind: 'human', reasonCode: 'file-target-invalid' }
    }
    return {
      kind: 'ready',
      evidence: {
        resolvedPath: target.displayPath,
        workspaceRelation: fs.contains(workspaceTarget, target) ? 'inside' : 'outside',
        pathEntryType: pathInfo?.type ?? 'missing',
        targetType: targetInfo?.type ?? 'missing',
        ...targetInfo?.type === 'file' && targetInfo.size !== undefined
          ? { size: targetInfo.size }
          : {},
        systemLocation: isProtectedSystemPath(processPath),
      },
    }
  }
}

/** Reject malformed metadata returned by a filesystem provider. */
function validPathInfo(info: FileProbePathInfo | undefined): boolean {
  return info === undefined || validOptionalSize(info.size)
}

/** Reject malformed metadata returned by a filesystem provider. */
function validTargetInfo(info: FileProbeInfo | undefined): boolean {
  return info === undefined || validOptionalSize(info.size)
}

/** DSH file sizes, when present, are finite non-negative integers. */
function validOptionalSize(size: number | undefined): boolean {
  return size === undefined || (Number.isSafeInteger(size) && size >= 0)
}

/** Whether a canonical process path belongs to a protected OS-managed location. */
export function isProtectedSystemPath(path: string): boolean {
  const normalized = path.replaceAll('\\', '/').replace(/\/{2,}/g, '/').replace(/\/$/, '').toLowerCase()
  if (normalized === '') return false
  const protectedRoots = [
    '/applications',
    '/bin',
    '/boot',
    '/dev',
    '/etc',
    '/library',
    '/lib',
    '/lib64',
    '/opt',
    '/private/etc',
    '/private/var',
    '/proc',
    '/root',
    '/run',
    '/sbin',
    '/srv',
    '/system',
    '/usr',
    '/var',
  ]
  if (protectedRoots.some(root => normalized === root || normalized.startsWith(`${root}/`))) return true
  if (/^[a-z]:\/(?:program files(?: \(x86\))?|programdata|windows)(?:\/|$)/.test(normalized)) return true
  return /^\/(?:users|home)\/[^/]+\/\.(?:bash_profile|bashrc|profile|zprofile|zshenv|zshrc)$/.test(normalized)
    || /^\/(?:users|home)\/[^/]+\/\.config\/(?:autostart(?:\/|$)|fish\/config\.fish$)/.test(normalized)
    || /^\/users\/[^/]+\/library\/(?:launchagents|launchdaemons)(?:\/|$)/.test(normalized)
    || /^\/home\/[^/]+\/\.config\/systemd(?:\/|$)/.test(normalized)
}

/** Normalize absolute execution paths for conservative alias comparison. */
function comparablePath(path: string): string {
  const normalized = path.replaceAll('\\', '/').replace(/\/{2,}/g, '/').replace(/\/$/, '')
  return /^[A-Za-z]:\//.test(normalized) ? normalized.toLowerCase() : normalized
}
