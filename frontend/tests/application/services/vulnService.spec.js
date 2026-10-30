import { describe, it, expect, vi } from 'vitest'
import vulnService from '@/application/services/vulnService'
import apiClient from '@/infrastructure/http/apiClient'

// Mock the apiClient module
vi.mock('@/infrastructure/http/apiClient', () => {
    return {
        default: {
            get: vi.fn(),
            post: vi.fn(),
        }
    }
})

describe('vulnService.js', () => {

    it('getVulns calls apiClient.get with default params when empty', async () => {
        const mockResponse = { data: [] }
        apiClient.get.mockResolvedValueOnce(mockResponse)

        const result = await vulnService.getVulns()

        expect(apiClient.get).toHaveBeenCalledWith('/vulns', {
            params: {}
        })
        expect(result).toEqual(mockResponse)
    })

    it('getVulns calls apiClient.get with specific params', async () => {
        const mockResponse = { data: [] }
        apiClient.get.mockResolvedValueOnce(mockResponse)

        const result = await vulnService.getVulns({ limit: 50, connectionId: 2 })

        expect(apiClient.get).toHaveBeenCalledWith('/vulns', {
            params: {
                limit: 50,
                connection_id: 2,
            }
        })
        expect(result).toEqual(mockResponse)
    })

    it('getVulns serializes server-side pagination, search, sorting and filter parameters', async () => {
        const mockResponse = { data: { items: [], total: 0, page: 1, page_size: 25, total_pages: 0 } }
        apiClient.get.mockResolvedValueOnce(mockResponse)

        const params = {
            page: 2,
            pageSize: 50,
            connectionId: 1,
            severity: 'CRITICAL',
            status: 'ACTIVE',
            agentName: 'db-server',
            cveId: 'CVE-2023-1234',
            packageName: 'openssl',
            search: 'memory leak',
            sortBy: 'detected_at',
            sortOrder: 'desc',
        }

        const result = await vulnService.getVulns(params)

        expect(apiClient.get).toHaveBeenCalledWith('/vulns', {
            params: {
                page: 2,
                page_size: 50,
                connection_id: 1,
                severity: 'CRITICAL',
                status: 'ACTIVE',
                agent_name: 'db-server',
                cve_id: 'CVE-2023-1234',
                package_name: 'openssl',
                search: 'memory leak',
                sort_by: 'detected_at',
                sort_order: 'desc',
            }
        })
        expect(result).toEqual(mockResponse)
    })

    it('syncVulns calls apiClient.post on /vulns/sync-all', async () => {
        const mockResponse = { data: { synced: 10 } }

        apiClient.post.mockResolvedValueOnce(mockResponse)

        const result = await vulnService.syncVulns()

        expect(apiClient.post).toHaveBeenCalledWith('/vulns/sync-all')
        expect(result).toEqual(mockResponse)
    })
})
