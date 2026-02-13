'use client'

import { useRef, useState, useEffect, useCallback } from 'react'
import { NODE_COLORS } from '../../config'
import { GraphData } from '../../types'
import styles from './PageBottomBar.module.css'

interface PageBottomBarProps {
  data: GraphData | undefined
  is3D: boolean
  showLabels: boolean
}

export function PageBottomBar({ data, is3D, showLabels }: PageBottomBarProps) {
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

  return (
    <div className={styles.bottomBar}>
      <div className={styles.legend}>
        <span className={styles.sectionTitle}>Node Types:</span>
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
          {Object.entries(NODE_COLORS)
            .filter(([key]) => key !== 'Default')
            .map(([type, color]) => (
              <div key={type} className={styles.legendItem}>
                <span
                  className={styles.legendColor}
                  style={{ backgroundColor: color }}
                />
                <span className={styles.legendLabel}>{type}</span>
              </div>
            ))}
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
          <div className={styles.statItem}>
            <span className={styles.statLabel}>View:</span>
            <span className={styles.statValue}>{is3D ? '3D' : '2D'}</span>
          </div>
          <div className={styles.statItem}>
            <span className={styles.statLabel}>Labels:</span>
            <span className={styles.statValue}>{showLabels ? 'On' : 'Off'}</span>
          </div>
        </div>
      </div>
    </div>
  )
}
