import { useRef } from 'react'
import { motion } from 'motion/react'
import { Upload } from 'lucide-react'
import { useDropzone } from 'react-dropzone'
import { cn } from '@/lib/utils'
import { formatBytes } from '@/lib/format'

const mainVariant = { initial: { x: 0, y: 0 }, animate: { x: 16, y: -16, opacity: 0.95 } }
const secondaryVariant = { initial: { opacity: 0 }, animate: { opacity: 1 } }

interface FileUploadProps {
  /** Currently selected file (controlled by the parent so it can reset after upload). */
  file: File | null
  onChange: (file: File | undefined) => void
  disabled?: boolean
  hint?: string
}

/** Single-file drop zone. Adapted from the Aceternity "File Upload" pattern to VEYLIX theme tokens. */
export function FileUpload({ file, onChange, disabled, hint }: FileUploadProps) {
  const inputRef = useRef<HTMLInputElement>(null)
  const { getRootProps, isDragActive } = useDropzone({
    multiple: false,
    noClick: true,
    disabled,
    onDrop: (accepted) => onChange(accepted[0]),
  })

  return (
    <div className="w-full" {...getRootProps()}>
      <motion.div
        role="button"
        tabIndex={disabled ? -1 : 0}
        aria-disabled={disabled}
        aria-label="Choose a file to upload"
        onClick={() => !disabled && inputRef.current?.click()}
        onKeyDown={(e) => {
          if (!disabled && (e.key === 'Enter' || e.key === ' ')) {
            e.preventDefault()
            inputRef.current?.click()
          }
        }}
        whileHover={disabled ? undefined : 'animate'}
        className={cn(
          'group/file relative block w-full overflow-hidden rounded-2xl border border-dashed bg-card shadow-[0_14px_34px_-22px_rgba(0,120,212,0.25)] p-8 transition-colors sm:p-10',
          disabled ? 'cursor-not-allowed opacity-60' : 'cursor-pointer hover:border-[#93C5FD] hover:bg-accent/50',
          isDragActive ? 'border-cyan bg-cyan/5' : 'border-[#93C5FD]',
        )}
      >
        <input
          ref={inputRef}
          type="file"
          className="sr-only"
          tabIndex={-1}
          disabled={disabled}
          onChange={(e) => {
            onChange(e.target.files?.[0])
            e.target.value = '' // allow re-selecting the same file
          }}
        />

        <div className="flex flex-col items-center justify-center text-center">
          <p className="text-base font-semibold">Upload file</p>
          <p className="mt-1.5 text-sm text-muted-foreground">Drag and drop a file here, or click to browse</p>
          {hint && <p className="mt-1 text-xs text-muted-foreground">{hint}</p>}

          <div className="relative mx-auto mt-8 w-full max-w-xl">
            {file ? (
              <motion.div
                layoutId="file-upload"
                className="relative z-10 mx-auto flex w-full flex-col gap-2 rounded-lg border border-border bg-background p-4 text-left shadow-sm"
              >
                <div className="flex items-center justify-between gap-4">
                  <p className="min-w-0 truncate text-sm font-medium" title={file.name}>
                    {file.name}
                  </p>
                  <p className="shrink-0 rounded-md bg-raised px-2 py-0.5 text-xs text-muted-foreground">{formatBytes(file.size)}</p>
                </div>
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
                  <span className="rounded bg-raised px-1.5 py-0.5">{file.type || 'unknown type'}</span>
                  <span>modified {new Date(file.lastModified).toLocaleDateString()}</span>
                </div>
              </motion.div>
            ) : (
              <>
                <motion.div
                  layoutId="file-upload"
                  variants={mainVariant}
                  transition={{ type: 'spring', stiffness: 300, damping: 20 }}
                  className="relative z-10 mx-auto flex h-28 w-full max-w-[8rem] items-center justify-center rounded-lg border border-border bg-background shadow-[0_10px_40px_rgba(0,0,0,0.12)]"
                >
                  {isDragActive ? (
                    <p className="flex flex-col items-center gap-1 text-sm text-cyan">
                      Drop it <Upload className="size-4" />
                    </p>
                  ) : (
                    <Upload className="size-5 text-muted-foreground" />
                  )}
                </motion.div>
                <motion.div
                  variants={secondaryVariant}
                  className="absolute inset-0 mx-auto flex h-28 w-full max-w-[8rem] items-center justify-center rounded-lg border border-dashed border-cyan bg-transparent opacity-0"
                />
              </>
            )}
          </div>
        </div>
      </motion.div>
    </div>
  )
}
