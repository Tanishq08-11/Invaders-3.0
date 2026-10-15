import { useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { CheckCircle2, X, XCircle } from 'lucide-react'
import { toast } from 'sonner'
import { uploadFile, useInvalidateFiles, type UploadHandle } from '@/api/files'
import { ApiError, isApiConfigured } from '@/api/client'
import { PageHeader, Panel } from '@/components/common/Panel'
import { Button, buttonVariants } from '@/components/ui/button'
import { FileUpload } from '@/components/ui/file-upload'
import { Progress, ProgressLabel, ProgressValue } from '@/components/ui/progress'
import { formatBytes } from '@/lib/format'
import { routes } from '@/lib/routes'
import { MAX_UPLOAD_BYTES, UPLOAD_GUIDANCE } from './shared'

type Phase = 'idle' | 'uploading' | 'success' | 'error'

export function UploadPage() {
  const [params] = useSearchParams()
  const folderId = params.get('folder')
  const handle = useRef<UploadHandle | null>(null)
  const invalidate = useInvalidateFiles()
  const [file, setFile] = useState<File | null>(null)
  const [phase, setPhase] = useState<Phase>('idle')
  const [progress, setProgress] = useState(0)
  const [message, setMessage] = useState<string | null>(null)

  const tooLarge = !!file && file.size > MAX_UPLOAD_BYTES
  const choose = (f: File | undefined) => {
    if (!f) return
    setFile(f)
    setPhase('idle')
    setProgress(0)
    setMessage(f.size > MAX_UPLOAD_BYTES ? `File exceeds the ${formatBytes(MAX_UPLOAD_BYTES)} limit.` : null)
  }

  const start = async () => {
    if (!file || tooLarge) return
    setPhase('uploading')
    setProgress(0)
    setMessage(null)
    handle.current = uploadFile(file, folderId, setProgress)
    try {
      await handle.current.promise // success is only reported after the backend accepts the file
      setPhase('success')
      setProgress(100)
      toast.success('Upload complete', { description: file.name })
      void invalidate()
    } catch (e) {
      if (e instanceof DOMException && e.name === 'AbortError') {
        setPhase('idle')
        setMessage('Upload cancelled.')
        return
      }
      const msg = e instanceof ApiError ? e.message : 'Upload failed.'
      setPhase('error')
      setMessage(msg)
      toast.error('Upload failed', { description: msg })
    }
  }

  const reset = () => {
    setFile(null)
    setPhase('idle')
    setProgress(0)
    setMessage(null)
  }

  return (
    <div>
      <PageHeader title="Upload" description="Send a file to a folder you are permitted to upload to. Permissions are enforced by the server." />
      <div className="grid gap-4 lg:grid-cols-3">
        {!isApiConfigured && (
          <p role="status" className="lg:col-span-3 rounded-lg border border-sev-medium/30 bg-sev-medium/10 px-3 py-2 text-sm text-sev-medium">
            Uploads are unavailable until the backend is connected.
          </p>
        )}

        <div className={file ? 'lg:col-span-2' : 'lg:col-span-3'}>
          <FileUpload file={file} onChange={choose} disabled={phase === 'uploading'} hint={UPLOAD_GUIDANCE} />
        </div>

        {file && (
          <Panel>
            {phase === 'uploading' && (
              <Progress value={progress} className="mb-4">
                <ProgressLabel>Uploading…</ProgressLabel>
                <ProgressValue className="ml-auto text-sm text-muted-foreground" />
              </Progress>
            )}
            {phase === 'success' && (
              <p className="mb-4 flex items-center gap-1.5 text-sm text-emerald-600">
                <CheckCircle2 className="size-4" /> Upload accepted by the server.
              </p>
            )}
            {message && phase !== 'success' && (
              <p role="alert" className="mb-4 flex items-center gap-1.5 text-sm text-sev-critical">
                <XCircle className="size-4" /> {message}
              </p>
            )}

            <div className="flex flex-wrap gap-2">
              {phase === 'uploading' ? (
                <Button variant="outline" onClick={() => handle.current?.abort()}>
                  Cancel upload
                </Button>
              ) : phase === 'success' ? (
                <>
                  <Link to={routes.employee.files} className={buttonVariants()}>
                    Back to files
                  </Link>
                  <Button variant="outline" onClick={reset}>
                    Upload another
                  </Button>
                </>
              ) : (
                <>
                  <Button onClick={() => void start()} disabled={!isApiConfigured || tooLarge}>
                    {phase === 'error' ? 'Retry upload' : 'Upload file'}
                  </Button>
                  <Button variant="ghost" onClick={reset}>
                    <X className="size-4" /> Remove
                  </Button>
                </>
              )}
            </div>
          </Panel>
        )}
      </div>
    </div>
  )
}
