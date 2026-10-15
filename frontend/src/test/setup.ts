// jsdom lacks a few browser APIs that motion / base-ui touch during render.
if (!window.matchMedia) {
  window.matchMedia = (query: string) =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }) as MediaQueryList
}

class NoopObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const g = globalThis as any
g.ResizeObserver ??= NoopObserver
g.IntersectionObserver ??= NoopObserver
