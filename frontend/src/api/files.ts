/**
 * PROVISIONAL employee file-portal contracts. These endpoints are PROPOSED and need
 * backend-team approval - see BACKEND_INTEGRATION.md. The backend must enforce permissions on
 * every request; the `permissions` flags below only drive UI affordances.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { z } from 'zod'
import { ApiError, apiUrl, isApiConfigured, notifyUnauthorized, request } from './client'
import { userSchema } from '@/auth/auth.types'

const str = z.string().nullish()
const lower = (v: unknown) => (typeof v === 'string' ? v.trim().toLowerCase() : v)

export const fileItemSchema = z.object({
  id: z.union([z.string(), z.number()]).transform(String),
  name: z.string(),
  kind: z.preprocess(lower, z.enum(['file', 'folder']).catch('file')),
  parent_id: z.union([z.string(), z.number()]).transform(String).nullish(),
  size_bytes: z.number().nullish(),
  mime_type: str,
  uploaded_at: str,
  owner: str,
  permissions: z
    .object({
      view: z.boolean().nullish(),
      upload: z.boolean().nullish(),
      download: z.boolean().nullish(),
    })
    .nullish(),
})
export type FileItem = z.infer<typeof fileItemSchema>

export const fileListSchema = z.union([
  z.array(fileItemSchema).transform((items) => ({ items, path: [] as { id: string; name: string }[], permissions: null })),
  z.object({
    items: z.array(fileItemSchema),
    path: z
      .array(z.object({ id: z.union([z.string(), z.number()]).transform(String), name: z.string() }))
      .nullish()
      .transform((p) => p ?? []),
    permissions: z
      .object({ view: z.boolean().nullish(), upload: z.boolean().nullish(), download: z.boolean().nullish() })
      .nullish(),
  }),
])
export type FileList = z.infer<typeof fileListSchema>

export const activitySchema = z.object({
  id: z.union([z.string(), z.number()]).transform(String),
  timestamp: z.string(),
  action: z.preprocess(lower, z.enum(['upload', 'download', 'access', 'denied']).catch('access')),
  file_name: str,
  result: z.preprocess(lower, z.enum(['success', 'denied', 'failed']).catch('failed')),
  detail: str,
})
export type ActivityEntry = z.infer<typeof activitySchema>
const activityListSchema = z.union([
  z.array(activitySchema),
  z.object({ items: z.array(activitySchema) }).transform((r) => r.items),
])

export const getFiles = (folderId: string | null, signal?: AbortSignal) =>
  request(`/api/v1/files${folderId ? `?folder_id=${encodeURIComponent(folderId)}` : ''}`, {
    schema: fileListSchema,
    signal,
  })
export const getActivity = (signal?: AbortSignal) =>
  request('/api/v1/files/activity', { schema: activityListSchema, signal })
export const getProfile = (signal?: AbortSignal) => request('/api/v1/employees/me', { schema: userSchema, signal })

export const useFiles = (folderId: string | null) =>
  useQuery({
    queryKey: ['files', folderId],
    queryFn: ({ signal }) => getFiles(folderId, signal),
    enabled: isApiConfigured,
    retry: false,
  })
export const useActivity = () =>
  useQuery({ queryKey: ['files', 'activity'], queryFn: ({ signal }) => getActivity(signal), enabled: isApiConfigured, retry: false })
export const useProfile = () =>
  useQuery({ queryKey: ['employees', 'me'], queryFn: ({ signal }) => getProfile(signal), enabled: isApiConfigured, retry: false })

// ---- Upload (multipart via XHR for progress + cancellation) ---------------------------------

export interface UploadHandle {
  promise: Promise<void>
  abort: () => void
}

export function uploadFile(file: File, folderId: string | null, onProgress: (pct: number) => void): UploadHandle {
  const xhr = new XMLHttpRequest()
  const promise = new Promise<void>((resolve, reject) => {
    if (!isApiConfigured) return reject(new ApiError('not_configured', 'Backend is not configured.'))
    const body = new FormData()
    body.append('file', file)
    if (folderId) body.append('folder_id', folderId)
    xhr.open('POST', apiUrl('/api/v1/files'))
    xhr.withCredentials = true
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(Math.round((e.loaded / e.total) * 100))
    xhr.onerror = () => reject(new ApiError('network', 'Upload failed - the backend could not be reached.'))
    xhr.onabort = () => reject(new DOMException('Upload cancelled', 'AbortError'))
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) return resolve()
      if (xhr.status === 401) notifyUnauthorized()
      const msg =
        xhr.status === 403
          ? 'You do not have permission to upload to this location.'
          : xhr.status === 413
            ? 'The file exceeds the maximum upload size.'
            : `Upload rejected by the backend (HTTP ${xhr.status}).`
      reject(new ApiError('http', msg, xhr.status))
    }
    xhr.send(body)
  })
  return { promise, abort: () => xhr.abort() }
}

export function useInvalidateFiles() {
  const qc = useQueryClient()
  return () => qc.invalidateQueries({ queryKey: ['files'] })
}

// ---- Download (authenticated fetch -> blob) -------------------------------------------------

export function useDownload() {
  return useMutation({
    mutationFn: async (file: FileItem) => {
      if (!isApiConfigured) throw new ApiError('not_configured', 'Backend is not configured.')
      let res: Response
      try {
        res = await fetch(apiUrl(`/api/v1/files/${encodeURIComponent(file.id)}/download`), { credentials: 'include' })
      } catch {
        throw new ApiError('network', 'Download failed - the backend could not be reached.')
      }
      if (res.status === 401) notifyUnauthorized()
      if (res.status === 403) throw new ApiError('http', 'You do not have permission to download this file.', 403)
      if (res.status === 404) throw new ApiError('http', 'This file no longer exists.', 404)
      if (!res.ok) throw new ApiError('http', `Download failed (HTTP ${res.status}).`, res.status)
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = file.name
      document.body.appendChild(a)
      a.click()
      a.remove()
      setTimeout(() => URL.revokeObjectURL(url), 10_000)
    },
  })
}
