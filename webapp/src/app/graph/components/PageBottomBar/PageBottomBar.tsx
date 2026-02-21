'use client'

import { useRef, useState, useEffect, useCallback, useMemo } from 'react'
import { NODE_COLORS } from '../../config'
import { GraphData } from '../../types'
import type { ViewMode } from '../ViewTabs'
import styles from './PageBottomBar.module.css'

interface PageBottomBarProps {
  data: GraphData | undefined
  is3D: boolean
  showLabels: boolean
  activeView: ViewMode
  // Table view filter props
  activeNodeTypes?: Set<string>
  nodeTypeCounts?: Record<string, number>
  onToggleNodeType?: (type: string) => void
  onSelectAllTypes?: () => void
  onClearAllTypes?: () => void
}

export function PageBottomBar({
  data,
  is3D,
  showLabels,
  activeView,
  activeNodeTypes,
  nodeTypeCounts,
  onToggleNodeType,
  onSelectAllTypes,
  onClearAllTypes,
}: PageBottomBarProps) {
  const scrollRef = useRef<HTMLDivElement>(null)
  const [canScrollLeft, setCanScrollLeft] = useState(false)
  const [canScrollRight, setCanScrollRight] = useState(false)

  const checkScroll = useCallback(() => {
    const el = scrollRef.current
    if (!el) return
    setCanScrollLeft(el.scrollLeft > 0)
    setCanScrollRight(el.scrollLeft + el.clientWidth < el.scrollWidth - 1)
  }, [])

  useEffect(() => {
    const el = scrollRef.current
    if (!el) return
    checkScroll()
    const observer = new ResizeObserver(checkScroll)
    observer.observe(el)
    return () => observer.disconnect()
  }, [checkScroll])

  const scroll = (direction: 'left' | 'right') => {
    const el = scrollRef.current
    if (!el) return
    el.scrollBy({ left: direction === 'left' ? -120 : 120, behavior: 'smooth' })
  }

  const sortedTypes = useMemo(
    () => nodeTypeCounts ? Object.keys(nodeTypeCounts).sort() : [],
    [nodeTypeCounts]
  )

  return (
    <div className={styles.bottomBar}>
      <div className={styles.legend}>
        <span className={styles.sectionTitle}>Filter:</span>
        {onToggleNodeType && (
          <div className={styles.chipActions}>
            <button className={styles.chipAction} onClick={onSelectAllTypes}>All</button>
            <button className={styles.chipAction} onClick={onClearAllTypes}>None</button>
          </div>
        )}
        {canScrollLeft && (
          <button className={styles.scrollBtn} onClick={() => scroll('left')}>
            ‹
          </button>
        )}
        <div
          ref={scrollRef}
          className={styles.legendItems}
          onScroll={checkScroll}
        >
          {sortedTypes.map(type => {
            const color = NODE_COLORS[type] || NODE_COLORS.Default
            const isActive = activeNodeTypes?.has(type) ?? true
            return (
              <button
                key={type}
                className={`${styles.typeChip} ${isActive ? styles.typeChipActive : ''}`}
                onClick={() => onToggleNodeType?.(type)}
                style={{ '--chip-color': color } as React.CSSProperties}
                aria-pressed={isActive}
              >
                <span className={styles.chipDot} />
                <span className={styles.chipLabel}>{type}</span>
                <span className={styles.chipCount}>{nodeTypeCounts?.[type] ?? 0}</span>
              </button>
            )
          })}
        </div>
        {canScrollRight && (
          <button className={styles.scrollBtn} onClick={() => scroll('right')}>
            ›
          </button>
        )}
      </div>

      <div className={styles.divider} />

      <div className={styles.stats}>
        <span className={styles.sectionTitle}>Stats:</span>
        <div className={styles.statItems}>
          <div className={styles.statItem}>
            <span className={styles.statLabel}>Nodes:</span>
            <span className={styles.statValue}>{data?.nodes.length ?? '-'}</span>
          </div>
          <div className={styles.statItem}>
            <span className={styles.statLabel}>Links:</span>
            <span className={styles.statValue}>{data?.links.length ?? '-'}</span>
          </div>
          {activeView === 'graph' && (
            <>
              <div className={styles.statItem}>
                <span className={styles.statLabel}>View:</span>
                <span className={styles.statValue}>{is3D ? '3D' : '2D'}</span>
              </div>
              <div className={styles.statItem}>
                <span className={styles.statLabel}>Labels:</span>
                <span className={styles.statValue}>{showLabels ? 'On' : 'Off'}</span>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
