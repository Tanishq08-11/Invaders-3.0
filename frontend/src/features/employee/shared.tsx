import { File, FileArchive, FileImage, FileSpreadsheet, FileText, Folder, Lock, ShieldQuestion } from 'lucide-react'
import type { FileItem } from '@/api/files'

export function FileIcon({ item, className = 'size-5' }: { item: FileItem; className?: string }) {
  if (item.kind === 'folder') return <Folder className={`${className} text-cyan`} />
  const m = (item.mime_type ?? '').toLowerCase()
  const ext = item.name.split('.').pop()?.toLowerCase() ?? ''
  if (m.startsWith('image/') || ['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp'].includes(ext)) return <FileImage className={className} />
  if (m.includes('sheet') || m.includes('csv') || ['xls', 'xlsx', 'csv'].includes(ext)) return <FileSpreadsheet className={className} />
  if (m.includes('zip') || ['zip', 'tar', 'gz', '7z', 'rar'].includes(ext)) return <FileArchive className={className} />
  if (m.startsWith('text/') || m.includes('pdf') || m.includes('word') || ['pdf', 'doc', 'docx', 'txt', 'md'].includes(ext))
    return <FileText className={className} />
  return <File className={className} />
}

/** Permission affordance. Purely informational - the backend enforces access on every request. */
export function PermissionBadge({ item }: { item: FileItem }) {
  const p = item.permissions
  if (!p) {
    return (
      <span className="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
        <ShieldQuestion className="size-3" /> Permission unavailable
      </span>
    )
  }
  if (p.view === false) {
    return (
      <span className="inline-flex items-center gap-1 text-[11px] text-sev-critical">
        <Lock className="size-3" /> Access denied
      </span>
    )
  }
  const parts = [p.view && 'View', p.download && 'Download', p.upload && 'Upload'].filter(Boolean)
  return <span className="text-[11px] text-muted-foreground">{parts.length ? parts.join(' · ') : 'Read only'}</span>
}

export const MAX_UPLOAD_BYTES = 100 * 1024 * 1024
// Guidance only: the backend is the authority on which types it accepts.
export const UPLOAD_GUIDANCE = 'Documents, spreadsheets, presentations, images, PDFs and archives up to 100 MB.'
