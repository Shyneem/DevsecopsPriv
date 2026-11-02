import { describe, it, expect } from 'vitest'
import {
  alignHour,
  badge,
  fmtDDMM,
  fmtHour,
  fmtYear,
  getSeverityCategory,
  getSeverityWeight,
  getSeverityLabel
} from '@/presentation/views/timeline/timelineFormatters'

describe('timelineFormatters', () => {
  it('formats day and year values', () => {
    const value = new Date('2026-03-08T14:33:00').getTime()
    expect(fmtDDMM(value)).toBe('08/03')
    expect(fmtYear(value)).toBe('2026')
  })

  it('formats hour at slot start', () => {
    const value = new Date('2026-03-08T14:33:00').getTime()
    expect(fmtHour(value)).toBe('14:00')
  })

  it('returns badge labels by type', () => {
    expect(badge('detection')).toBe('NUEVA')
    expect(badge('resolution')).toBe('RESUELTA')
    expect(badge('mixed')).toBe('MIXTO')
  })

  it('aligns timestamp to the nearest hour start', () => {
    const value = new Date('2026-03-08T14:33:59').getTime()
    const aligned = alignHour(value)
    const alignedDate = new Date(aligned)
    expect(alignedDate.getMinutes()).toBe(0)
    expect(alignedDate.getSeconds()).toBe(0)
  })

  it('classifies severity categories accurately', () => {
    expect(getSeverityCategory('CRITICAL')).toBe('critical')
    expect(getSeverityCategory('Critica')).toBe('critical')
    expect(getSeverityCategory('HIGH')).toBe('high')
    expect(getSeverityCategory('Alta')).toBe('high')
    expect(getSeverityCategory('Medium')).toBe('medium')
    expect(getSeverityCategory('Media')).toBe('medium')
    expect(getSeverityCategory('Low')).toBe('low')
    expect(getSeverityCategory('unknown')).toBe('low')
  })

  it('assigns correct weight to severities', () => {
    expect(getSeverityWeight('critical')).toBe(4)
    expect(getSeverityWeight('high')).toBe(3)
    expect(getSeverityWeight('medium')).toBe(2)
    expect(getSeverityWeight('low')).toBe(1)
  })

  it('returns localized labels for severities', () => {
    expect(getSeverityLabel('critical')).toBe('CRÍTICA')
    expect(getSeverityLabel('high')).toBe('ALTA')
    expect(getSeverityLabel('medium')).toBe('MEDIA')
    expect(getSeverityLabel('low')).toBe('BAJA')
  })
})
