import { Fragment } from 'react'
import { Link } from 'react-router-dom'
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb'

export interface Crumb {
  label: string
  to?: string
}

/** Breadcrumb trail for nested pages. The last item is the current page. */
export function Crumbs({ items }: { items: Crumb[] }) {
  return (
    <Breadcrumb className="mb-3">
      <BreadcrumbList className="text-xs">
        {items.map((c, i) => {
          const last = i === items.length - 1
          return (
            <Fragment key={`${c.label}-${i}`}>
              <BreadcrumbItem className="min-w-0">
                {last || !c.to ? (
                  <BreadcrumbPage className="max-w-56 truncate font-mono">{c.label}</BreadcrumbPage>
                ) : (
                  <BreadcrumbLink render={<Link to={c.to} />}>{c.label}</BreadcrumbLink>
                )}
              </BreadcrumbItem>
              {!last && <BreadcrumbSeparator />}
            </Fragment>
          )
        })}
      </BreadcrumbList>
    </Breadcrumb>
  )
}
